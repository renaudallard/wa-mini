/*
 * wa-mini - Minimal WhatsApp Primary Device
 * CLI Entry Point
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/wait.h>
#include <sodium.h>

#include "wa-mini.h"
#include "control.h"

/* Global verbose flag for debug logging */
int wa_verbose = 0;

/* External registration functions */
extern int wa_do_registration(const char *phone, const char *method);
extern int wa_do_verification(const char *phone, const char *code, wa_account_t *account);

/* External companion linking functions */
extern int wa_link_display(const char *phone);

/* External store functions */
typedef struct wa_store wa_store_t;
extern wa_store_t *wa_store_open(const char *data_dir);
extern void wa_store_close(wa_store_t *store);
extern int wa_store_account_save(wa_store_t *store, const wa_account_t *account);

/* Global context for signal handler */
static wa_ctx_t *g_ctx = NULL;

/* Signal handler - only use async-signal-safe functions */
static void signal_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM) {
        const char msg[] = "\nShutting down...\n";
        (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
        if (g_ctx != NULL) {
            wa_stop(g_ctx);
        }
    } else if (sig == SIGHUP) {
        const char msg[] = "Received SIGHUP\n";
        (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
        /* TODO: Reload configuration */
    } else if (sig == SIGCHLD) {
        /* Reap zombie children */
        while (waitpid(-1, NULL, WNOHANG) > 0) {
            /* Continue reaping */
        }
    }
}

/* State change callback */
static void on_state_change(wa_ctx_t *ctx, wa_state_t state, void *userdata)
{
    (void)ctx;
    (void)userdata;
    fprintf(stderr, "State: %s\n", wa_state_string(state));
}

/* Print usage */
static void print_usage(const char *progname)
{
    fprintf(stderr,
        "wa-mini - Minimal WhatsApp Primary Device (Multi-Account)\n"
        "Version: %s\n"
        "\n"
        "Usage: %s <command> [options]\n"
        "\n"
        "Commands:\n"
        "  register <phone>   Register new phone number (+1234567890)\n"
        "  verify <code>      Enter SMS verification code for pending registration\n"
        "  link [phone]       Display QR/link code for companion linking\n"
        "  list               List all registered accounts\n"
        "  status [phone]     Show connection and device status\n"
        "  daemon [--stop]    Run all accounts as background daemon\n"
        "  logout <phone>     Deregister account and clear credentials\n"
        "  version            Show current WhatsApp version being used\n"
        "\n"
        "Options:\n"
        "  -d, --data <path>     Data directory (default: ~/.wa-mini)\n"
        "  -a, --account <phone> Select account for command\n"
        "  -s, --stop            Stop the running daemon\n"
        "  -v, --verbose         Verbose logging\n"
        "  -h, --help            Show this help\n"
        "\n"
        "IPC Commands (when daemon running):\n"
        "  list, status          Query daemon for live account status\n"
        "  daemon --stop         Gracefully stop the daemon\n"
        "\n"
        "Examples:\n"
        "  %s register +15551234567\n"
        "  %s verify 123456\n"
        "  %s link +15551234567\n"
        "  %s list\n"
        "  %s daemon\n"
        "  %s daemon --stop\n"
        "  %s logout +15551234567\n",
        WA_MINI_VERSION, progname,
        progname, progname, progname, progname, progname, progname, progname);
}

/* Command: list */
static int cmd_list(wa_ctx_t *ctx, const char *data_dir)
{
    WA_DEBUG("listing accounts, data_dir=%s", data_dir ? data_dir : "(default)");

    /* Try daemon first */
    int fd = control_connect(data_dir);
    if (fd >= 0) {
        WA_DEBUG("connected to daemon, sending LIST command");
        control_send_command(fd, "LIST");
        char response[4096];
        if (control_recv_response(fd, response, sizeof(response)) == 0) {
            WA_DEBUG("received response from daemon");
            /* Parse and display daemon response */
            printf("Daemon running. Active accounts:\n");
            printf("%s", response);
            close(fd);
        } else {
            WA_DEBUG("failed to receive response from daemon");
            close(fd);
        }
        /* Still show database accounts below */
    } else {
        WA_DEBUG("daemon not running, using direct database access");
    }

    /* Fall back to direct database access */
    wa_account_t *accounts = NULL;
    int count = 0;

    wa_error_t err = wa_account_list(ctx, &accounts, &count);
    if (err != WA_OK) {
        fprintf(stderr, "Error: %s\n", wa_error_string(err));
        return 1;
    }

    if (count == 0) {
        printf("No registered accounts.\n");
        return 0;
    }

    printf("\nRegistered accounts:\n");
    printf("%-20s %-10s %s\n", "Phone", "Status", "Registered");
    printf("%-20s %-10s %s\n", "--------------------", "----------", "-------------------");

    for (int i = 0; i < count; i++) {
        char time_str[32];
        struct tm *tm = localtime((time_t *)&accounts[i].registered_at);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);

        printf("%-20s %-10s %s\n",
               accounts[i].phone,
               accounts[i].active ? "Active" : "Inactive",
               time_str);
    }

    wa_account_free(accounts, count);
    return 0;
}

/* Command: status */
static int cmd_status(wa_ctx_t *ctx, const char *data_dir, const char *phone)
{
    /* Try daemon first for runtime status */
    int fd = control_connect(data_dir);
    if (fd >= 0) {
        if (phone != NULL) {
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "STATUS %s", phone);
            control_send_command(fd, cmd);
        } else {
            control_send_command(fd, "LIST");
        }
        char response[4096];
        if (control_recv_response(fd, response, sizeof(response)) == 0) {
            printf("Daemon status:\n%s\n", response);
        }
        close(fd);
    } else {
        printf("Daemon: not running\n\n");
    }

    if (phone != NULL) {
        wa_account_t account;
        wa_error_t err = wa_account_get(ctx, phone, &account);
        if (err != WA_OK) {
            fprintf(stderr, "Error: Account not found: %s\n", phone);
            return 1;
        }

        printf("Account: %s\n", account.phone);
        printf("Database status: %s\n", account.active ? "Active" : "Inactive");
        printf("Registration ID: %u\n", account.registration_id);

        char time_str[32];
        struct tm *tm = localtime((time_t *)&account.registered_at);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);
        printf("Registered: %s\n", time_str);
    } else {
        /* Show all accounts status */
        cmd_list(ctx, data_dir);
    }

    printf("\nConnection: %s\n", wa_state_string(wa_get_state(ctx)));

    char version[32];
    wa_version_get(ctx, version, sizeof(version));
    printf("WhatsApp Version: %s\n", version);

    return 0;
}

/* Command: version */
static int cmd_version(wa_ctx_t *ctx)
{
    char version[32];
    wa_version_get(ctx, version, sizeof(version));
    printf("WhatsApp Version: %s\n", version);
    return 0;
}

/* Command: register */
static int cmd_register(wa_ctx_t *ctx, const char *data_dir,
                        const char *phone, const char *method)
{
    WA_DEBUG("register phone=%s method=%s", phone ? phone : "(null)", method ? method : "sms");

    if (phone == NULL || phone[0] != '+') {
        fprintf(stderr, "Error: Phone number must start with '+' (e.g., +15551234567)\n");
        return 1;
    }

    /* Try daemon first */
    int fd = control_connect(data_dir);
    if (fd >= 0) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "REGISTER %s %s", phone, method ? method : "sms");
        control_send_command(fd, cmd);
        char response[1024];
        if (control_recv_response(fd, response, sizeof(response)) == 0) {
            printf("%s", response);
        }
        close(fd);
        return 0;
    }

    /* Fall back to direct registration */
    /* Check if account already exists */
    wa_account_t existing;
    if (wa_account_get(ctx, phone, &existing) == WA_OK) {
        fprintf(stderr, "Error: Account %s already registered\n", phone);
        fprintf(stderr, "Use 'wa-mini logout %s' to remove it first\n", phone);
        return 1;
    }

    return wa_do_registration(phone, method);
}

/* Command: verify */
static int cmd_verify(wa_ctx_t *ctx, const char *data_dir,
                      const char *phone, const char *code)
{
    WA_DEBUG("verify phone=%s code=%s", phone ? phone : "(null)", code ? "******" : "(null)");

    if (code == NULL || strlen(code) != 6) {
        fprintf(stderr, "Error: Verification code must be 6 digits\n");
        return 1;
    }

    if (phone == NULL) {
        fprintf(stderr, "Error: Phone number required for verification\n");
        fprintf(stderr, "Usage: wa-mini verify -a +15551234567 123456\n");
        return 1;
    }

    /* Try daemon first - it will save and start the account automatically */
    int fd = control_connect(data_dir);
    if (fd >= 0) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "VERIFY %s %s", phone, code);
        control_send_command(fd, cmd);
        char response[1024];
        if (control_recv_response(fd, response, sizeof(response)) == 0) {
            printf("%s", response);
        }
        close(fd);
        return 0;
    }

    /* Fall back to direct verification (no daemon running) */
    /* Create account structure */
    wa_account_t account;
    sodium_memzero(&account, sizeof(account));
    strncpy(account.phone, phone, sizeof(account.phone) - 1);

    /* Perform verification (generates keys) */
    if (wa_do_verification(phone, code, &account) != 0) {
        return 1;
    }

    /* Save account to database */
    wa_store_t *store = wa_store_open(data_dir);
    if (store != NULL) {
        account.active = 1;
        account.registered_at = time(NULL);
        if (wa_store_account_save(store, &account) == 0) {
            printf("Account %s saved successfully\n", phone);
        } else {
            fprintf(stderr, "Warning: Failed to save account\n");
        }
        wa_store_close(store);
    } else {
        fprintf(stderr, "Warning: Could not open database\n");
    }

    printf("Phone: %s\n", account.phone);
    printf("Registration ID: %u\n", account.registration_id);

    (void)ctx;
    return 0;
}

/* Command: link */
static int cmd_link(wa_ctx_t *ctx, const char *phone)
{
    (void)ctx;

    /* If no phone specified, check for registered accounts */
    if (phone == NULL) {
        wa_account_t *accounts = NULL;
        int count = 0;
        if (wa_account_list(ctx, &accounts, &count) == WA_OK && count > 0) {
            phone = accounts[0].phone;
            wa_account_free(accounts, count);
        }
    }

    return wa_link_display(phone);
}

/* Command: logout */
static int cmd_logout(wa_ctx_t *ctx, const char *data_dir, const char *phone)
{
    if (phone == NULL) {
        fprintf(stderr, "Error: Phone number required\n");
        return 1;
    }

    /* Try daemon first - it will stop child and delete account */
    int fd = control_connect(data_dir);
    if (fd >= 0) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "LOGOUT %s", phone);
        control_send_command(fd, cmd);
        char response[1024];
        if (control_recv_response(fd, response, sizeof(response)) == 0) {
            printf("%s", response);
        }
        close(fd);
        return 0;
    }

    /* Daemon not running - do direct logout */
    /* Try to unregister from WhatsApp servers first */
    printf("Unregistering %s from WhatsApp servers...\n", phone);
    wa_error_t err = wa_unregister(ctx, phone);
    if (err != WA_OK) {
        fprintf(stderr, "Warning: Could not unregister from server: %s\n", wa_error_string(err));
        fprintf(stderr, "Proceeding with local account removal...\n");
    } else {
        printf("Successfully unregistered from WhatsApp servers.\n");
    }

    /* Delete local account data */
    err = wa_account_delete(ctx, phone);
    if (err != WA_OK) {
        fprintf(stderr, "Error: %s\n", wa_error_string(err));
        return 1;
    }

    printf("Account %s removed.\n", phone);
    return 0;
}

/* Run daemon for a single account (called from fork) */
void daemon_run_account(const char *data_dir, const char *phone)
{
    WA_DEBUG("child process starting for phone=%s", phone);

    wa_ctx_t *ctx = wa_ctx_new(data_dir);
    if (ctx == NULL) {
        fprintf(stderr, "[%s] Failed to create context\n", phone);
        _exit(1);
    }

    wa_set_state_callback(ctx, on_state_change, NULL);

    WA_DEBUG("[%s] connecting to WhatsApp", phone);
    wa_error_t err = wa_connect(ctx, phone);
    if (err != WA_OK) {
        WA_DEBUG("[%s] connection failed: %s", phone, wa_error_string(err));
        fprintf(stderr, "[%s] Error connecting: %s\n", phone, wa_error_string(err));
        wa_ctx_free(ctx);
        _exit(1);
    }

    WA_DEBUG("[%s] connection established, entering main loop", phone);
    printf("[%s] Connected\n", phone);
    wa_run(ctx);

    WA_DEBUG("[%s] main loop exited, disconnecting", phone);
    wa_disconnect(ctx);
    wa_ctx_free(ctx);
    _exit(0);
}

/* Command: daemon */
static int cmd_daemon(wa_ctx_t *ctx, const char *data_dir, int stop_daemon)
{
    WA_DEBUG("daemon command, stop=%d", stop_daemon);

    /* Handle --stop option */
    if (stop_daemon) {
        int fd = control_connect(data_dir);
        if (fd < 0) {
            fprintf(stderr, "Daemon not running\n");
            return 1;
        }
        control_send_command(fd, "STOP");
        char response[256];
        control_recv_response(fd, response, sizeof(response));
        close(fd);
        printf("Daemon stopping...\n");
        return 0;
    }

    /* Check if daemon already running */
    if (control_daemon_running(data_dir)) {
        fprintf(stderr, "Daemon already running\n");
        return 1;
    }

    /* Create daemon context */
    daemon_ctx_t *dctx = daemon_ctx_new(data_dir);
    if (dctx == NULL) {
        fprintf(stderr, "Failed to create daemon context\n");
        return 1;
    }

    /* Load and start all active accounts */
    wa_account_t *accounts = NULL;
    int count = 0;
    int started = 0;

    wa_error_t err = wa_account_list(ctx, &accounts, &count);
    if (err == WA_OK && count > 0) {
        for (int i = 0; i < count; i++) {
            if (accounts[i].active) {
                if (daemon_start_account(dctx, accounts[i].phone) == 0) {
                    started++;
                }
            }
        }
        wa_account_free(accounts, count);
    }

    printf("Daemon started with %d account(s)\n", started);
    printf("Use 'wa-mini register/verify' to add accounts (auto-started)\n");
    printf("Control socket: %s/%s\n",
           dctx->data_dir ? dctx->data_dir : "~/.wa-mini",
           CONTROL_SOCKET_NAME);

    /* Run main loop */
    int ret = daemon_run(dctx);

    daemon_ctx_free(dctx);
    return ret;
}

/* Main */
int main(int argc, char *argv[])
{
    const char *data_dir = NULL;
    const char *account = NULL;
    int verbose = 0;
    int stop_daemon = 0;

    /* Long options */
    static struct option long_options[] = {
        {"data", required_argument, 0, 'd'},
        {"account", required_argument, 0, 'a'},
        {"stop", no_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    /* Parse options */
    int opt;
    while ((opt = getopt_long(argc, argv, "d:a:svh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'd':
            data_dir = optarg;
            break;
        case 'a':
            account = optarg;
            break;
        case 's':
            stop_daemon = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Set global verbose flag for debug logging */
    wa_verbose = verbose;

    /* Check for command */
    if (optind >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[optind];

    /* Create context */
    wa_ctx_t *ctx = wa_ctx_new(data_dir);
    if (ctx == NULL) {
        fprintf(stderr, "Error: Failed to initialize\n");
        return 1;
    }

    /* Set up signal handlers */
    g_ctx = ctx;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGCHLD, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    int ret = 0;

    /* Execute command */
    if (strcmp(command, "list") == 0) {
        ret = cmd_list(ctx, data_dir);
    } else if (strcmp(command, "status") == 0) {
        const char *phone = (optind + 1 < argc) ? argv[optind + 1] : account;
        ret = cmd_status(ctx, data_dir, phone);
    } else if (strcmp(command, "version") == 0) {
        ret = cmd_version(ctx);
    } else if (strcmp(command, "register") == 0) {
        const char *phone = (optind + 1 < argc) ? argv[optind + 1] : NULL;
        const char *method = (optind + 2 < argc) ? argv[optind + 2] : "sms";
        ret = cmd_register(ctx, data_dir, phone, method);
    } else if (strcmp(command, "verify") == 0) {
        const char *code = (optind + 1 < argc) ? argv[optind + 1] : NULL;
        const char *phone = account;  /* Use -a/--account option */
        ret = cmd_verify(ctx, data_dir, phone, code);
    } else if (strcmp(command, "link") == 0) {
        const char *phone = (optind + 1 < argc) ? argv[optind + 1] : account;
        ret = cmd_link(ctx, phone);
    } else if (strcmp(command, "logout") == 0) {
        const char *phone = (optind + 1 < argc) ? argv[optind + 1] : account;
        ret = cmd_logout(ctx, data_dir, phone);
    } else if (strcmp(command, "daemon") == 0) {
        ret = cmd_daemon(ctx, data_dir, stop_daemon);
    } else {
        fprintf(stderr, "Error: Unknown command: %s\n", command);
        print_usage(argv[0]);
        ret = 1;
    }

    wa_ctx_free(ctx);
    g_ctx = NULL;

    return ret;
}
