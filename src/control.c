/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Control Socket IPC Implementation
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE  /* for usleep */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>

#include "control.h"
#include "wa-mini.h"

/* Forward declarations for external functions */
extern void daemon_run_account(const char *data_dir, const char *phone);

/* Store functions */
typedef struct wa_store wa_store_t;
extern wa_store_t *wa_store_open(const char *data_dir);
extern void wa_store_close(wa_store_t *store);
extern int wa_store_account_save(wa_store_t *store, const wa_account_t *account);
extern int wa_store_account_delete(wa_store_t *store, const char *phone);

/* Maximum command line length */
#define MAX_CMD_LEN 256
#define MAX_RESPONSE_LEN 4096

/* Initial child array capacity */
#define INITIAL_CHILD_CAPACITY 8

/* Global daemon context for signal handler */
static daemon_ctx_t *g_daemon_ctx = NULL;

/* Build socket path */
static int build_socket_path(const char *data_dir, char *path, size_t size)
{
    const char *dir = data_dir;
    if (dir == NULL) {
        const char *home = getenv("HOME");
        if (home == NULL) return -1;
        snprintf(path, size, "%s/.wa-mini/%s", home, CONTROL_SOCKET_NAME);
    } else {
        snprintf(path, size, "%s/%s", dir, CONTROL_SOCKET_NAME);
    }
    return 0;
}

/* Build PID file path */
static int build_pid_path(const char *data_dir, char *path, size_t size)
{
    const char *dir = data_dir;
    if (dir == NULL) {
        const char *home = getenv("HOME");
        if (home == NULL) return -1;
        snprintf(path, size, "%s/.wa-mini/%s", home, CONTROL_PID_NAME);
    } else {
        snprintf(path, size, "%s/%s", dir, CONTROL_PID_NAME);
    }
    return 0;
}

/* Write PID file */
static int write_pid_file(const char *data_dir)
{
    char path[256];
    if (build_pid_path(data_dir, path, sizeof(path)) < 0)
        return -1;

    FILE *f = fopen(path, "w");
    if (f == NULL) return -1;

    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
    chmod(path, 0600);
    return 0;
}

/* Remove PID file */
static void remove_pid_file(const char *data_dir)
{
    char path[256];
    if (build_pid_path(data_dir, path, sizeof(path)) == 0) {
        unlink(path);
    }
}

/* Create control socket */
static int create_control_socket(const char *data_dir)
{
    WA_DEBUG("creating control socket");

    char path[108];  /* Match sun_path size */
    if (build_socket_path(data_dir, path, sizeof(path)) < 0)
        return -1;

    /* Remove existing socket */
    unlink(path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    /* Set restrictive permissions before bind */
    mode_t old_umask = umask(0177);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        umask(old_umask);
        close(fd);
        return -1;
    }

    umask(old_umask);

    if (listen(fd, 1) < 0) {
        close(fd);
        unlink(path);
        return -1;
    }

    return fd;
}

/* Accept client connection */
static int accept_client(int listen_fd)
{
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);

    int fd = accept(listen_fd, (struct sockaddr *)&addr, &addrlen);
    if (fd < 0) return -1;

    /* Set timeout for client operations */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    return fd;
}

/* Send response to client */
static int send_ok(int fd, const char *json)
{
    char buf[MAX_RESPONSE_LEN];
    int len = snprintf(buf, sizeof(buf), "OK %s\n", json ? json : "{}");
    return write(fd, buf, len) == len ? 0 : -1;
}

static int send_error(int fd, const char *code, const char *message)
{
    char buf[MAX_RESPONSE_LEN];
    int len = snprintf(buf, sizeof(buf),
        "ERR {\"code\":\"%s\",\"message\":\"%s\"}\n", code, message);
    return write(fd, buf, len) == len ? 0 : -1;
}

/* Find child by phone */
static daemon_child_t *find_child_by_phone(daemon_ctx_t *ctx, const char *phone)
{
    for (int i = 0; i < ctx->child_count; i++) {
        if (strcmp(ctx->children[i].phone, phone) == 0 &&
            ctx->children[i].pid > 0) {
            return &ctx->children[i];
        }
    }
    return NULL;
}

/* Command handlers */
static int handle_ping(int client_fd)
{
    return send_ok(client_fd, "{\"status\":\"pong\"}");
}

static int handle_list(int client_fd, daemon_ctx_t *ctx)
{
    char json[MAX_RESPONSE_LEN];
    int offset = 0;

    offset += snprintf(json + offset, sizeof(json) - offset, "{\"accounts\":[");

    int first = 1;
    for (int i = 0; i < ctx->child_count; i++) {
        if (ctx->children[i].pid <= 0) continue;

        if (!first) {
            offset += snprintf(json + offset, sizeof(json) - offset, ",");
        }
        first = 0;

        const char *status_str;
        switch (ctx->children[i].status) {
            case CHILD_STATUS_STARTING:  status_str = "starting"; break;
            case CHILD_STATUS_CONNECTED: status_str = "connected"; break;
            case CHILD_STATUS_ERROR:     status_str = "error"; break;
            default:                     status_str = "unknown"; break;
        }

        offset += snprintf(json + offset, sizeof(json) - offset,
            "{\"phone\":\"%s\",\"pid\":%d,\"status\":\"%s\"}",
            ctx->children[i].phone, ctx->children[i].pid, status_str);
    }

    snprintf(json + offset, sizeof(json) - offset, "]}");

    return send_ok(client_fd, json);
}

static int handle_status(int client_fd, daemon_ctx_t *ctx, const char *phone)
{
    if (phone == NULL || phone[0] == '\0') {
        return send_error(client_fd, "INVALID_ARGS", "Phone number required");
    }

    daemon_child_t *child = find_child_by_phone(ctx, phone);
    if (child == NULL) {
        return send_error(client_fd, "NOT_FOUND", "Account not running");
    }

    const char *status_str;
    switch (child->status) {
        case CHILD_STATUS_STARTING:  status_str = "starting"; break;
        case CHILD_STATUS_CONNECTED: status_str = "connected"; break;
        case CHILD_STATUS_ERROR:     status_str = "error"; break;
        default:                     status_str = "unknown"; break;
    }

    char json[256];
    snprintf(json, sizeof(json),
        "{\"phone\":\"%s\",\"pid\":%d,\"status\":\"%s\"}",
        child->phone, child->pid, status_str);

    return send_ok(client_fd, json);
}

static int handle_link(int client_fd, daemon_ctx_t *ctx, const char *phone)
{
    (void)ctx;

    if (phone == NULL) {
        return send_error(client_fd, "INVALID_ARGS", "Phone number required");
    }

    return send_error(client_fd, "NOT_IMPLEMENTED",
        "Use CLI directly for linking");
}

static int handle_logout(int client_fd, daemon_ctx_t *ctx, const char *phone)
{
    if (phone == NULL || phone[0] != '+') {
        return send_error(client_fd, "INVALID_ARGS", "Phone number required");
    }

    /* Stop running child process if any */
    daemon_child_t *child = find_child_by_phone(ctx, phone);
    if (child != NULL) {
        kill(child->pid, SIGTERM);
        /* Wait briefly for child to exit */
        int status;
        waitpid(child->pid, &status, 0);
        child->pid = 0;
        child->status = CHILD_STATUS_ERROR;
    }

    /* Delete account from database */
    wa_store_t *store = wa_store_open(ctx->data_dir);
    if (store == NULL) {
        return send_error(client_fd, "STORAGE", "Failed to open database");
    }

    int deleted = wa_store_account_delete(store, phone) == 0;
    wa_store_close(store);

    if (!deleted) {
        return send_error(client_fd, "NOT_FOUND", "Account not found");
    }

    char json[128];
    snprintf(json, sizeof(json),
        "{\"phone\":\"%s\",\"stopped\":true,\"deleted\":true}", phone);
    return send_ok(client_fd, json);
}

static int handle_reload(int client_fd, daemon_ctx_t *ctx)
{
    /* Load accounts from database and start any new ones */
    wa_ctx_t *wa_ctx = wa_ctx_new(ctx->data_dir);
    if (wa_ctx == NULL) {
        return send_error(client_fd, "INTERNAL", "Failed to create context");
    }

    wa_account_t *accounts = NULL;
    int count = 0;
    wa_error_t err = wa_account_list(wa_ctx, &accounts, &count);
    if (err != WA_OK) {
        wa_ctx_free(wa_ctx);
        return send_error(client_fd, "STORAGE", "Failed to list accounts");
    }

    int started = 0;
    for (int i = 0; i < count; i++) {
        if (!accounts[i].active) continue;

        /* Check if already running */
        if (find_child_by_phone(ctx, accounts[i].phone) != NULL) continue;

        /* Start new account */
        if (daemon_start_account(ctx, accounts[i].phone) == 0) {
            started++;
        }
    }

    wa_account_free(accounts, count);
    wa_ctx_free(wa_ctx);

    char json[64];
    snprintf(json, sizeof(json), "{\"started\":%d}", started);
    return send_ok(client_fd, json);
}

static int handle_stop(int client_fd, daemon_ctx_t *ctx)
{
    ctx->running = 0;
    return send_ok(client_fd, "{\"stopping\":true}");
}

/* Parse command line */
static int parse_command(const char *line, char *cmd, char *arg1, char *arg2)
{
    cmd[0] = '\0';
    arg1[0] = '\0';
    arg2[0] = '\0';

    /* Skip leading whitespace */
    while (*line == ' ' || *line == '\t') line++;

    /* Parse command */
    int i = 0;
    while (*line && *line != ' ' && *line != '\t' &&
           *line != '\n' && i < MAX_CMD_LEN - 1) {
        cmd[i++] = *line++;
    }
    cmd[i] = '\0';

    /* Skip whitespace */
    while (*line == ' ' || *line == '\t') line++;

    /* Parse first argument */
    i = 0;
    while (*line && *line != ' ' && *line != '\t' &&
           *line != '\n' && i < MAX_CMD_LEN - 1) {
        arg1[i++] = *line++;
    }
    arg1[i] = '\0';

    /* Skip whitespace */
    while (*line == ' ' || *line == '\t') line++;

    /* Parse second argument */
    i = 0;
    while (*line && *line != ' ' && *line != '\t' &&
           *line != '\n' && i < MAX_CMD_LEN - 1) {
        arg2[i++] = *line++;
    }
    arg2[i] = '\0';

    return cmd[0] != '\0' ? 0 : -1;
}

/* Dispatch command */
static int dispatch_command(int client_fd, daemon_ctx_t *ctx)
{
    char line[MAX_CMD_LEN];
    ssize_t n = read(client_fd, line, sizeof(line) - 1);
    if (n <= 0) return -1;
    line[n] = '\0';

    char cmd[MAX_CMD_LEN], arg1[MAX_CMD_LEN], arg2[MAX_CMD_LEN];
    if (parse_command(line, cmd, arg1, arg2) < 0) {
        return send_error(client_fd, "INVALID_CMD", "Empty command");
    }

    WA_DEBUG("received command: %s %s %s", cmd, arg1, arg2);

    if (strcmp(cmd, "PING") == 0) {
        return handle_ping(client_fd);
    } else if (strcmp(cmd, "LIST") == 0) {
        return handle_list(client_fd, ctx);
    } else if (strcmp(cmd, "STATUS") == 0) {
        return handle_status(client_fd, ctx, arg1);
    } else if (strcmp(cmd, "LINK") == 0) {
        return handle_link(client_fd, ctx, arg1);
    } else if (strcmp(cmd, "LOGOUT") == 0) {
        return handle_logout(client_fd, ctx, arg1);
    } else if (strcmp(cmd, "RELOAD") == 0) {
        return handle_reload(client_fd, ctx);
    } else if (strcmp(cmd, "STOP") == 0) {
        return handle_stop(client_fd, ctx);
    } else {
        return send_error(client_fd, "UNKNOWN_CMD", "Unknown command");
    }
}

/* Reap exited children */
static void reap_children(daemon_ctx_t *ctx)
{
    int status;
    pid_t pid;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        /* Find and mark child as exited */
        for (int i = 0; i < ctx->child_count; i++) {
            if (ctx->children[i].pid == pid) {
                WA_DEBUG("child process %d (%s) exited with status %d",
                         pid, ctx->children[i].phone, WEXITSTATUS(status));
                fprintf(stderr, "Account %s exited (pid %d)\n",
                        ctx->children[i].phone, pid);
                ctx->children[i].pid = 0;
                ctx->children[i].status = CHILD_STATUS_ERROR;
                break;
            }
        }
    }
}

/* Signal handler for daemon */
static void daemon_signal_handler(int sig)
{
    if (g_daemon_ctx == NULL) return;

    if (sig == SIGCHLD) {
        /* Write to signal pipe to wake up poll() */
        char c = 'C';
        (void)write(g_daemon_ctx->signal_pipe[1], &c, 1);
    } else if (sig == SIGINT || sig == SIGTERM) {
        g_daemon_ctx->running = 0;
        /* Write to signal pipe to wake up poll() */
        char c = 'Q';
        (void)write(g_daemon_ctx->signal_pipe[1], &c, 1);
    }
}

/* Create daemon context */
daemon_ctx_t *daemon_ctx_new(const char *data_dir)
{
    WA_DEBUG("creating daemon context, data_dir=%s", data_dir ? data_dir : "(default)");

    daemon_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) return NULL;

    if (data_dir != NULL) {
        ctx->data_dir = strdup(data_dir);
    } else {
        const char *home = getenv("HOME");
        if (home != NULL) {
            char path[256];
            snprintf(path, sizeof(path), "%s/.wa-mini", home);
            ctx->data_dir = strdup(path);
        }
    }

    /* Create signal pipe */
    if (pipe(ctx->signal_pipe) < 0) {
        free(ctx->data_dir);
        free(ctx);
        return NULL;
    }

    /* Make pipe non-blocking */
    fcntl(ctx->signal_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(ctx->signal_pipe[1], F_SETFL, O_NONBLOCK);

    /* Create control socket */
    ctx->control_fd = create_control_socket(ctx->data_dir);
    if (ctx->control_fd < 0) {
        close(ctx->signal_pipe[0]);
        close(ctx->signal_pipe[1]);
        free(ctx->data_dir);
        free(ctx);
        return NULL;
    }

    /* Allocate child array */
    ctx->child_capacity = INITIAL_CHILD_CAPACITY;
    ctx->children = calloc(ctx->child_capacity, sizeof(daemon_child_t));
    if (ctx->children == NULL) {
        close(ctx->control_fd);
        close(ctx->signal_pipe[0]);
        close(ctx->signal_pipe[1]);
        free(ctx->data_dir);
        free(ctx);
        return NULL;
    }

    ctx->running = 1;

    /* Write PID file */
    write_pid_file(ctx->data_dir);

    return ctx;
}

/* Free daemon context */
void daemon_ctx_free(daemon_ctx_t *ctx)
{
    if (ctx == NULL) return;

    /* Close control socket and remove socket file */
    if (ctx->control_fd >= 0) {
        close(ctx->control_fd);
        char path[256];
        if (build_socket_path(ctx->data_dir, path, sizeof(path)) == 0) {
            unlink(path);
        }
    }

    /* Remove PID file */
    remove_pid_file(ctx->data_dir);

    close(ctx->signal_pipe[0]);
    close(ctx->signal_pipe[1]);

    free(ctx->children);
    free(ctx->data_dir);
    free(ctx);
}

/* Start account process */
int daemon_start_account(daemon_ctx_t *ctx, const char *phone)
{
    WA_DEBUG("starting account process for %s", phone);

    /* Check if already running */
    if (find_child_by_phone(ctx, phone) != NULL) {
        WA_DEBUG("account %s already running", phone);
        return -1;
    }

    /* Grow array if needed */
    if (ctx->child_count >= ctx->child_capacity) {
        int new_cap = ctx->child_capacity * 2;
        daemon_child_t *new_children = realloc(ctx->children,
            new_cap * sizeof(daemon_child_t));
        if (new_children == NULL) return -1;
        ctx->children = new_children;
        ctx->child_capacity = new_cap;
    }

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        /* Child process */
        close(ctx->control_fd);
        close(ctx->signal_pipe[0]);
        close(ctx->signal_pipe[1]);

        /* Reset signals to default */
        signal(SIGCHLD, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);

        daemon_run_account(ctx->data_dir, phone);
        _exit(1);  /* Should not reach here */
    }

    /* Parent - record child */
    daemon_child_t *child = &ctx->children[ctx->child_count++];
    child->pid = pid;
    strncpy(child->phone, phone, sizeof(child->phone) - 1);
    child->phone[sizeof(child->phone) - 1] = '\0';
    child->status = CHILD_STATUS_STARTING;

    fprintf(stderr, "Started account %s (pid %d)\n", phone, pid);
    return 0;
}

/* Stop account process */
int daemon_stop_account(daemon_ctx_t *ctx, const char *phone)
{
    daemon_child_t *child = find_child_by_phone(ctx, phone);
    if (child == NULL) return -1;

    kill(child->pid, SIGTERM);
    return 0;
}

/* Run daemon main loop */
int daemon_run(daemon_ctx_t *ctx)
{
    WA_DEBUG("entering daemon main loop");
    g_daemon_ctx = ctx;

    /* Set up signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = daemon_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    struct pollfd fds[2];
    fds[0].fd = ctx->control_fd;
    fds[0].events = POLLIN;
    fds[1].fd = ctx->signal_pipe[0];
    fds[1].events = POLLIN;

    while (ctx->running) {
        int ret = poll(fds, 2, 5000);

        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Control socket connection */
        if (fds[0].revents & POLLIN) {
            WA_DEBUG("incoming control socket connection");
            int client = accept_client(ctx->control_fd);
            if (client >= 0) {
                dispatch_command(client, ctx);
                close(client);
            }
        }

        /* Signal received */
        if (fds[1].revents & POLLIN) {
            char buf[16];
            while (read(ctx->signal_pipe[0], buf, sizeof(buf)) > 0) {
                /* Drain pipe */
            }
            reap_children(ctx);
        }
    }

    WA_DEBUG("daemon loop exited, stopping %d children", ctx->child_count);

    /* Stop all children */
    for (int i = 0; i < ctx->child_count; i++) {
        if (ctx->children[i].pid > 0) {
            WA_DEBUG("sending SIGTERM to child %d (%s)", ctx->children[i].pid, ctx->children[i].phone);
            kill(ctx->children[i].pid, SIGTERM);
        }
    }

    /* Wait for children to exit */
    int timeout = 50;  /* 5 seconds */
    while (timeout-- > 0) {
        int all_exited = 1;
        for (int i = 0; i < ctx->child_count; i++) {
            if (ctx->children[i].pid > 0) {
                int status;
                pid_t result = waitpid(ctx->children[i].pid, &status, WNOHANG);
                if (result == 0) {
                    all_exited = 0;
                } else if (result > 0) {
                    ctx->children[i].pid = 0;
                }
            }
        }
        if (all_exited) break;
        usleep(100000);  /* 100ms */
    }

    /* Force kill any remaining */
    for (int i = 0; i < ctx->child_count; i++) {
        if (ctx->children[i].pid > 0) {
            kill(ctx->children[i].pid, SIGKILL);
            waitpid(ctx->children[i].pid, NULL, 0);
        }
    }

    g_daemon_ctx = NULL;
    return 0;
}

/* Connect to daemon control socket */
int control_connect(const char *data_dir)
{
    char path[108];  /* Match sun_path size */
    if (build_socket_path(data_dir, path, sizeof(path)) < 0)
        return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    return fd;
}

/* Send command to daemon */
int control_send_command(int fd, const char *cmd)
{
    char buf[MAX_CMD_LEN];
    int len = snprintf(buf, sizeof(buf), "%s\n", cmd);
    return write(fd, buf, len) == len ? 0 : -1;
}

/* Receive response from daemon */
int control_recv_response(int fd, char *buf, size_t size)
{
    ssize_t n = read(fd, buf, size - 1);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return 0;
}

/* Check if daemon is running */
int control_daemon_running(const char *data_dir)
{
    int fd = control_connect(data_dir);
    if (fd < 0) return 0;

    /* Try ping */
    if (control_send_command(fd, "PING") == 0) {
        char buf[256];
        if (control_recv_response(fd, buf, sizeof(buf)) == 0) {
            close(fd);
            return 1;
        }
    }

    close(fd);
    return 0;
}
