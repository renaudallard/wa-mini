/*
 * wa-mini - Minimal WhatsApp Primary Device
 * TCP Socket Management
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <poll.h>
#include <time.h>

#include "wa-mini.h"

/* WhatsApp server endpoints */
#define WA_HOST_PRIMARY   "g.whatsapp.net"
#define WA_HOST_FALLBACK  "e1.whatsapp.net"
#define WA_PORT           443
#define WA_PORT_ALT       5222

/* Connection timeouts */
#define CONNECT_TIMEOUT_MS  30000
#define READ_TIMEOUT_MS     60000
#define WRITE_TIMEOUT_MS    30000

/* Reconnect backoff */
#define RECONNECT_MIN_MS    1000
#define RECONNECT_MAX_MS    300000  /* 5 minutes */

typedef struct {
    int fd;
    int connected;
    time_t last_activity;
    time_t last_reconnect;
    int reconnect_delay_ms;

    /* Buffer for partial reads */
    uint8_t read_buf[65536];
    size_t read_buf_len;
    size_t read_buf_pos;

    /* Buffer for partial writes */
    uint8_t write_buf[65536];
    size_t write_buf_len;
    size_t write_buf_pos;
} wa_socket_t;

/* Set socket non-blocking */
static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Set socket options */
static int set_socket_options(int fd)
{
    int opt = 1;

    /* Disable Nagle's algorithm for low latency */
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
        return -1;
    }

    /* Enable keepalive */
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
        return -1;
    }

#ifdef TCP_KEEPIDLE
    /* Set keepalive parameters (Linux) */
    int idle = 60;
    int interval = 10;
    int count = 6;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
#endif

    return 0;
}

/* Create new socket context */
wa_socket_t *wa_socket_new(void)
{
    wa_socket_t *sock = calloc(1, sizeof(*sock));
    if (sock == NULL) return NULL;

    sock->fd = -1;
    sock->reconnect_delay_ms = RECONNECT_MIN_MS;

    return sock;
}

/* Free socket context */
void wa_socket_free(wa_socket_t *sock)
{
    if (sock == NULL) return;

    if (sock->fd >= 0) {
        close(sock->fd);
    }

    free(sock);
}

/* Connect to WhatsApp server */
int wa_socket_connect(wa_socket_t *sock, const char *host, int port)
{
    struct addrinfo hints, *result, *rp;
    char port_str[16];
    int ret;

    if (host == NULL) host = WA_HOST_PRIMARY;
    if (port <= 0) port = WA_PORT;

    WA_DEBUG("connecting to %s:%d", host, port);

    /* Close existing connection */
    if (sock->fd >= 0) {
        close(sock->fd);
        sock->fd = -1;
        sock->connected = 0;
    }

    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;

    ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    /* Try each address */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock->fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock->fd < 0) continue;

        if (set_socket_options(sock->fd) < 0) {
            close(sock->fd);
            sock->fd = -1;
            continue;
        }

        if (set_nonblocking(sock->fd) < 0) {
            close(sock->fd);
            sock->fd = -1;
            continue;
        }

        /* Non-blocking connect */
        ret = connect(sock->fd, rp->ai_addr, rp->ai_addrlen);
        if (ret < 0 && errno != EINPROGRESS) {
            close(sock->fd);
            sock->fd = -1;
            continue;
        }

        /* Wait for connection with timeout */
        struct pollfd pfd = {
            .fd = sock->fd,
            .events = POLLOUT,
        };

        ret = poll(&pfd, 1, CONNECT_TIMEOUT_MS);
        if (ret <= 0) {
            close(sock->fd);
            sock->fd = -1;
            continue;
        }

        /* Check for connection error */
        int err = 0;
        socklen_t errlen = sizeof(err);
        if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0) {
            close(sock->fd);
            sock->fd = -1;
            continue;
        }

        /* Connected */
        WA_DEBUG("TCP connection established");
        sock->connected = 1;
        sock->last_activity = time(NULL);
        sock->reconnect_delay_ms = RECONNECT_MIN_MS;
        break;
    }

    freeaddrinfo(result);

    if (!sock->connected) {
        WA_DEBUG("connection failed");
        return -1;
    }

    return 0;
}

/* Disconnect */
void wa_socket_disconnect(wa_socket_t *sock)
{
    if (sock->fd >= 0) {
        close(sock->fd);
        sock->fd = -1;
    }
    sock->connected = 0;
    sock->read_buf_len = 0;
    sock->read_buf_pos = 0;
    sock->write_buf_len = 0;
    sock->write_buf_pos = 0;
}

/* Check if connected */
int wa_socket_is_connected(wa_socket_t *sock)
{
    return sock->connected;
}

/* Write data (buffered) */
int wa_socket_write(wa_socket_t *sock, const uint8_t *data, size_t len)
{
    if (!sock->connected) return -1;

    while (len > 0) {
        ssize_t written = write(sock->fd, data, len);

        if (written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Wait for socket to be writable */
                struct pollfd pfd = {
                    .fd = sock->fd,
                    .events = POLLOUT,
                };

                int ret = poll(&pfd, 1, WRITE_TIMEOUT_MS);
                if (ret <= 0) {
                    sock->connected = 0;
                    return -1;
                }
                continue;
            }

            sock->connected = 0;
            return -1;
        }

        data += written;
        len -= written;
        sock->last_activity = time(NULL);
    }

    return 0;
}

/* Read data with timeout */
int wa_socket_read(wa_socket_t *sock, uint8_t *data, size_t len, int timeout_ms)
{
    if (!sock->connected) return -1;

    size_t total = 0;

    while (total < len) {
        struct pollfd pfd = {
            .fd = sock->fd,
            .events = POLLIN,
        };

        int ret = poll(&pfd, 1, timeout_ms);
        if (ret < 0) {
            if (errno == EINTR) continue;
            sock->connected = 0;
            return -1;
        }

        if (ret == 0) {
            /* Timeout - return what we have */
            return total;
        }

        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            sock->connected = 0;
            return -1;
        }

        ssize_t n = read(sock->fd, data + total, len - total);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            sock->connected = 0;
            return -1;
        }

        if (n == 0) {
            /* EOF */
            sock->connected = 0;
            return total > 0 ? (int)total : -1;
        }

        total += n;
        sock->last_activity = time(NULL);
    }

    return total;
}

/* Read exact number of bytes */
int wa_socket_read_exact(wa_socket_t *sock, uint8_t *data, size_t len, int timeout_ms)
{
    size_t total = 0;
    time_t start = time(NULL);

    while (total < len) {
        int remaining_timeout = timeout_ms;
        if (timeout_ms > 0) {
            time_t diff_sec = time(NULL) - start;
            /* Avoid overflow and handle large elapsed times */
            if (diff_sec < 0 || diff_sec > timeout_ms / 1000 + 1) {
                return -1;  /* Timeout or time went backwards */
            }
            long elapsed_ms = (long)diff_sec * 1000;
            remaining_timeout = timeout_ms - (int)elapsed_ms;
            if (remaining_timeout <= 0) return -1;  /* Timeout */
        }

        int n = wa_socket_read(sock, data + total, len - total, remaining_timeout);
        if (n < 0) return -1;
        if (n == 0) return -1;  /* Timeout or EOF before getting all data */
        total += n;
    }

    return total;
}

/* Write framed message (3-byte big-endian length prefix) */
int wa_socket_write_frame(wa_socket_t *sock, const uint8_t *data, size_t len)
{
    WA_DEBUG("writing frame, len=%zu", len);

    if (len > 0xFFFFFF) return -1;  /* Max 24-bit length */

    uint8_t header[3] = {
        (len >> 16) & 0xFF,
        (len >> 8) & 0xFF,
        len & 0xFF,
    };

    if (wa_socket_write(sock, header, 3) < 0) return -1;
    if (len > 0) {
        if (wa_socket_write(sock, data, len) < 0) return -1;
    }

    return 0;
}

/* Read framed message */
int wa_socket_read_frame(wa_socket_t *sock, uint8_t *data, size_t max_len,
                         size_t *out_len, int timeout_ms)
{
    uint8_t header[3];

    if (wa_socket_read_exact(sock, header, 3, timeout_ms) < 0) {
        return -1;
    }

    size_t len = ((size_t)header[0] << 16) | ((size_t)header[1] << 8) | header[2];

    if (len > max_len) {
        return -1;  /* Frame too large */
    }

    if (len > 0) {
        if (wa_socket_read_exact(sock, data, len, timeout_ms) < 0) {
            return -1;
        }
    }

    *out_len = len;
    WA_DEBUG("read frame, len=%zu", len);
    return 0;
}

/* Get time since last activity */
time_t wa_socket_idle_time(wa_socket_t *sock)
{
    return time(NULL) - sock->last_activity;
}

/* Reconnect with exponential backoff */
int wa_socket_reconnect(wa_socket_t *sock)
{
    WA_DEBUG("attempting reconnect, delay=%dms", sock->reconnect_delay_ms);

    time_t now = time(NULL);

    /* Check if we should wait before reconnecting */
    if (sock->last_reconnect > 0) {
        time_t diff_sec = now - sock->last_reconnect;
        /* Avoid overflow: if diff is very large, we've waited long enough */
        if (diff_sec < 0 || diff_sec > 3600) {
            /* Time went backwards or waited over an hour - proceed */
        } else {
            unsigned long elapsed_ms = (unsigned long)diff_sec * 1000;
            if (elapsed_ms < (unsigned long)sock->reconnect_delay_ms) {
                /* Sleep remaining time */
                unsigned long remaining = (unsigned long)sock->reconnect_delay_ms - elapsed_ms;
                usleep((useconds_t)(remaining * 1000));
            }
        }
    }

    sock->last_reconnect = time(NULL);

    /* Try primary host first */
    if (wa_socket_connect(sock, WA_HOST_PRIMARY, WA_PORT) == 0) {
        return 0;
    }

    /* Try alternate port */
    if (wa_socket_connect(sock, WA_HOST_PRIMARY, WA_PORT_ALT) == 0) {
        return 0;
    }

    /* Try fallback host */
    if (wa_socket_connect(sock, WA_HOST_FALLBACK, WA_PORT) == 0) {
        return 0;
    }

    /* Increase backoff */
    sock->reconnect_delay_ms *= 2;
    if (sock->reconnect_delay_ms > RECONNECT_MAX_MS) {
        sock->reconnect_delay_ms = RECONNECT_MAX_MS;
    }

    return -1;
}

/* Get file descriptor for poll/select */
int wa_socket_get_fd(wa_socket_t *sock)
{
    return sock->fd;
}
