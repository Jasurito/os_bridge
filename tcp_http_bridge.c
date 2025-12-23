#define _GNU_SOURCE
#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>

#define DEFAULT_PORT 8080
#define DEFAULT_BACKEND_HOST "127.0.0.1"
#define DEFAULT_BACKEND_PORT 8000
#define MAX_REQUEST_SIZE (50 * 1024 * 1024)
#define RECV_BUF 8192

static char g_backend_host[256] = DEFAULT_BACKEND_HOST;
static int g_backend_port = DEFAULT_BACKEND_PORT;

struct header_collector {
    char buffer[32768];
    int pos;
};

struct connection_info {
    char *post_data;
    size_t post_data_size;
    size_t post_data_capacity;
};

// Case-insensitive strstr
static char *stristr(const char *haystack, const char *needle) {
    if (!*needle) return (char*)haystack;
    for (; *haystack; ++haystack) {
        if (tolower(*haystack) == tolower(*needle)) {
            const char *h = haystack;
            const char *n = needle;
            for (; *h && *n; ++h, ++n) {
                if (tolower(*h) != tolower(*n)) break;
            }
            if (!*n) return (char*)haystack;
        }
    }
    return NULL;
}

// Add CORS headers to response
static void add_cors_headers(struct MHD_Response *response) {
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, Origin");
    MHD_add_response_header(response, "Access-Control-Max-Age", "86400");
}

// Handle OPTIONS preflight request
static enum MHD_Result handle_options(struct MHD_Connection *connection) {
    const char *empty = "";
    struct MHD_Response *response = MHD_create_response_from_buffer(
        0, (void*)empty, MHD_RESPMEM_PERSISTENT);
    
    add_cors_headers(response);
    
    int ret = MHD_queue_response(connection, MHD_HTTP_NO_CONTENT, response);
    MHD_destroy_response(response);
    
    printf("Handled OPTIONS preflight request\n");
    fflush(stdout);
    
    return ret;
}

// Connect to backend
static int connect_backend(const char *host, int port) {
    int sfd = -1;
    struct sockaddr_in server_addr;
    
    // Create socket
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1) {
        perror("socket");
        return -1;
    }
    
    // Setup server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Convert IP address from string to binary
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sfd);
        return -1;
    }
    
    // Connect to backend
    if (connect(sfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sfd);
        return -1;
    }
    
    return sfd;
}

// Send all bytes
static int send_all(int fd, const void *buf, size_t len) {
    size_t sent = 0;
    const char *p = (const char*)buf;
    while (sent < len) {
        ssize_t r = send(fd, p + sent, len - sent, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)r;
    }
    return 0;
}

// Read all response
static char *read_all_response(int fd, size_t *out_len) {
    size_t cap = RECV_BUF;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    
    while (1) {
        ssize_t r = recv(fd, buf + len, cap - len, 0);
        if (r > 0) {
            len += (size_t)r;
            if (cap - len < RECV_BUF/2) {
                cap *= 2;
                if (cap > MAX_REQUEST_SIZE) {
                    free(buf);
                    return NULL;
                }
                char *nb = realloc(buf, cap);
                if (!nb) { free(buf); return NULL; }
                buf = nb;
            }
        } else if (r == 0) {
            break;
        } else {
            if (errno == EINTR) continue;
            break;
        }
    }
    *out_len = len;
    return buf;
}

/* Header iterator callback */
static enum MHD_Result collect_headers(void *cls, enum MHD_ValueKind kind,
                          const char *key, const char *value) {
    struct header_collector *hc = cls;
    
    /* Skip certain headers */
    if (strcasecmp(key, "Host") == 0) return MHD_YES;
    if (strcasecmp(key, "Connection") == 0) return MHD_YES;
    if (strcasecmp(key, "Content-Length") == 0) return MHD_YES;
    if (strcasecmp(key, "Origin") == 0) return MHD_YES;
    
    /* Add header to buffer */
    int added = snprintf(hc->buffer + hc->pos, sizeof(hc->buffer) - hc->pos,
                        "%s: %s\r\n", key, value);
    if (added > 0 && hc->pos + added < sizeof(hc->buffer)) {
        hc->pos += added;
    }
    
    return MHD_YES;
}

/* MHD access handler */
static enum MHD_Result answer_to_connection(void *cls,
                                struct MHD_Connection *connection,
                                const char *url,
                                const char *method,
                                const char *version,
                                const char *upload_data,
                                size_t *upload_data_size,
                                void **con_cls) {
    
    /* Handle OPTIONS preflight */
    if (strcmp(method, "OPTIONS") == 0) {
        if (*con_cls == NULL) {
            *con_cls = (void*)1; // Mark as processed
            return handle_options(connection);
        }
        return MHD_YES;
    }
    
    if (*con_cls == NULL) {
        struct connection_info *ci = calloc(1, sizeof(*ci));
        if (!ci) return MHD_NO;
        *con_cls = ci;
        return MHD_YES;
    }

    struct connection_info *ci = *con_cls;

    /* Collect POST data */
    if (*upload_data_size > 0) {
        if (ci->post_data_size + *upload_data_size > MAX_REQUEST_SIZE) {
            return MHD_NO;
        }
        if (ci->post_data_capacity < ci->post_data_size + *upload_data_size + 1) {
            size_t newcap = ci->post_data_capacity ? ci->post_data_capacity * 2 : 4096;
            while (newcap < ci->post_data_size + *upload_data_size + 1) newcap *= 2;
            char *nb = realloc(ci->post_data, newcap);
            if (!nb) return MHD_NO;
            ci->post_data = nb;
            ci->post_data_capacity = newcap;
        }
        memcpy(ci->post_data + ci->post_data_size, upload_data, *upload_data_size);
        ci->post_data_size += *upload_data_size;
        *upload_data_size = 0;
        return MHD_YES;
    }
    
    /* Build HTTP request */
    char *request = malloc(MAX_REQUEST_SIZE);
    if (!request) {
        fprintf(stderr, "Failed to allocate request buffer\n");
        return MHD_NO;
    }
    
    int pos = 0;
    
    /* Request line */
    pos += snprintf(request + pos, MAX_REQUEST_SIZE - pos,
                   "%s %s HTTP/1.1\r\n", method, url);
    
    /* Host header */
    pos += snprintf(request + pos, MAX_REQUEST_SIZE - pos,
                   "Host: %s:%d\r\n", g_backend_host, g_backend_port);
    
    /* Collect all client headers */
    struct header_collector hc = {.pos = 0};
    MHD_get_connection_values(connection, MHD_HEADER_KIND, collect_headers, &hc);
    
    /* Add collected headers */
    if (hc.pos > 0 && pos + hc.pos < MAX_REQUEST_SIZE) {
        memcpy(request + pos, hc.buffer, hc.pos);
        pos += hc.pos;
    }
    
    /* Content-Length for POST */
    if (strcmp(method, "POST") == 0 && ci->post_data_size > 0) {
        pos += snprintf(request + pos, MAX_REQUEST_SIZE - pos,
                       "Content-Length: %zu\r\n", ci->post_data_size);
    }
    
    /* Connection close */
    pos += snprintf(request + pos, MAX_REQUEST_SIZE - pos,
                   "Connection: close\r\n\r\n");
    
    /* Add body */
    if (ci->post_data_size > 0 && pos + ci->post_data_size < MAX_REQUEST_SIZE) {
        memcpy(request + pos, ci->post_data, ci->post_data_size);
        pos += ci->post_data_size;
    }
    
    printf("Forwarding %s %s (%d bytes)\n", method, url, pos);
    fflush(stdout);
    
    /* Connect and send */
    int fd = connect_backend(g_backend_host, g_backend_port);
    if (fd < 0) {
        fprintf(stderr, "Backend connection failed\n");
        free(request);
        const char *err = "Backend connection failed";
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        add_cors_headers(response);
        int ret = MHD_queue_response(connection, MHD_HTTP_BAD_GATEWAY, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    if (send_all(fd, request, pos) < 0) {
        fprintf(stderr, "Failed to send to backend\n");
        free(request);
        close(fd);
        const char *err = "Failed to send to backend";
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        add_cors_headers(response);
        int ret = MHD_queue_response(connection, MHD_HTTP_BAD_GATEWAY, response);
        MHD_destroy_response(response);
        return ret;
    }
    free(request);
    
    /* Read response */
    size_t response_len;
    char *backend_response = read_all_response(fd, &response_len);
    close(fd);
    
    if (!backend_response || response_len == 0) {
        fprintf(stderr, "Empty backend response\n");
        if (backend_response) free(backend_response);
        const char *err = "Empty backend response";
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
        add_cors_headers(response);
        int ret = MHD_queue_response(connection, MHD_HTTP_BAD_GATEWAY, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    printf("Received %zu bytes from backend\n", response_len);
    fflush(stdout);
    
    /* Parse status line */
    int status_code = 200;
    const char *status_start = strchr(backend_response, ' ');
    if (status_start) {
        status_code = atoi(status_start + 1);
    }
    
    /* Find body (after headers) */
    const char *body_start = strstr(backend_response, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
    } else {
        body_start = strstr(backend_response, "\n\n");
        if (body_start) {
            body_start += 2;
        } else {
            body_start = backend_response;
        }
    }
    
    size_t body_len = response_len - (body_start - backend_response);
    char *body = malloc(body_len + 1);
    if (!body) {
        fprintf(stderr, "Failed to allocate body buffer\n");
        free(backend_response);
        return MHD_NO;
    }
    memcpy(body, body_start, body_len);
    body[body_len] = '\0';
    
    /* Extract Content-Type from response headers */
    char ct_buffer[256] = "application/octet-stream";
    const char *ct_start = stristr(backend_response, "Content-Type:");
    if (ct_start && ct_start < body_start) {
        ct_start += 13; /* strlen("Content-Type:") */
        while (*ct_start == ' ' || *ct_start == '\t') ct_start++;
        const char *ct_end = strpbrk(ct_start, "\r\n");
        if (ct_end) {
            size_t ct_len = ct_end - ct_start;
            if (ct_len < sizeof(ct_buffer)) {
                memcpy(ct_buffer, ct_start, ct_len);
                ct_buffer[ct_len] = '\0';
            }
        }
    }
    
    free(backend_response);
    
    /* Send response to client */
    struct MHD_Response *response = MHD_create_response_from_buffer(
        body_len, body, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(response, "Content-Type", ct_buffer);
    
    /* Add CORS headers */
    add_cors_headers(response);
    
    int ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    
    printf("Sent response: %d (%zu bytes)\n", status_code, body_len);
    fflush(stdout);
    
    return ret;
}

/* Cleanup */
static void request_completed(void *cls, struct MHD_Connection *connection,
                             void **con_cls, enum MHD_RequestTerminationCode toe) {
    if (con_cls && *con_cls) {
        struct connection_info *ci = *con_cls;
        if (ci != (void*)1) { // Not an OPTIONS request marker
            free(ci->post_data);
            free(ci);
        }
        *con_cls = NULL;
    }
}

int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--backend") && i+1 < argc) {
            char hb[256]; int p;
            char *s = argv[i+1];
            char *colon = strchr(s, ':');
            if (colon) {
                size_t hlen = colon - s;
                if (hlen >= sizeof(hb)) hlen = sizeof(hb)-1;
                memcpy(hb, s, hlen);
                hb[hlen] = '\0';
                p = atoi(colon+1);
                strncpy(g_backend_host, hb, sizeof(g_backend_host)-1);
                g_backend_port = p;
            }
            i++;
        } else if (!strcmp(argv[i], "--port") && i+1 < argc) {
            port = atoi(argv[i+1]);
            i++;
        }
    }

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_THREAD_PER_CONNECTION, port, NULL, NULL,
        &answer_to_connection, NULL,
        MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
        MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start HTTP daemon\n");
        return 1;
    }

    printf("HTTP proxy with CORS running: :%d -> %s:%d\n", port, g_backend_host, g_backend_port);
    fflush(stdout);

    for (;;) pause();

    MHD_stop_daemon(daemon);
    return 0;
}