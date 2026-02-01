/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Control Socket IPC
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#ifndef CONTROL_H
#define CONTROL_H

#include <sys/types.h>

/* Control socket filename */
#define CONTROL_SOCKET_NAME "control.sock"
#define CONTROL_PID_NAME "daemon.pid"

/* Child process status */
#define CHILD_STATUS_STARTING   0
#define CHILD_STATUS_CONNECTED  1
#define CHILD_STATUS_ERROR      2

/* Child process tracking */
typedef struct {
    pid_t pid;
    char phone[20];
    int status;
} daemon_child_t;

/* Daemon context */
typedef struct {
    char *data_dir;
    int control_fd;
    int signal_pipe[2];
    daemon_child_t *children;
    int child_count;
    int child_capacity;
    int running;
} daemon_ctx_t;

/* Daemon API */
daemon_ctx_t *daemon_ctx_new(const char *data_dir);
void daemon_ctx_free(daemon_ctx_t *ctx);
int daemon_run(daemon_ctx_t *ctx);
int daemon_start_account(daemon_ctx_t *ctx, const char *phone);
int daemon_stop_account(daemon_ctx_t *ctx, const char *phone);

/* CLI client API */
int control_connect(const char *data_dir);
int control_send_command(int fd, const char *cmd);
int control_recv_response(int fd, char *buf, size_t size);

/* Check if daemon is running */
int control_daemon_running(const char *data_dir);

#endif /* CONTROL_H */
