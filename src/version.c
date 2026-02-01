/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Version Auto-Update
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#include "wa-mini.h"

/* Version sources */
#define APKPURE_URL "https://apkpure.com/whatsapp-messenger/com.whatsapp"
#define FALLBACK_VERSION "2.26.3.79"

/* Check interval (seconds) */
#define VERSION_CHECK_INTERVAL (24 * 60 * 60)  /* 24 hours */

/* External store functions */
typedef struct wa_store wa_store_t;
extern int wa_store_config_get(wa_store_t *store, const char *key, char *value, size_t size);
extern int wa_store_config_set(wa_store_t *store, const char *key, const char *value);

/*
 * Parse version string (e.g., "2.26.3.79")
 * Returns 0 if valid, -1 if invalid
 */
static int parse_version(const char *str, int *major, int *minor, int *patch, int *build)
{
    /* Initialize to zero in case sscanf partially succeeds */
    *major = *minor = *patch = *build = 0;

    if (str == NULL) return -1;
    if (sscanf(str, "%d.%d.%d.%d", major, minor, patch, build) != 4) {
        return -1;
    }
    if (*major < 2 || *major > 9) return -1;  /* Sanity check */
    return 0;
}

/*
 * Compare versions: returns >0 if a > b, <0 if a < b, 0 if equal
 */
static int compare_versions(const char *a, const char *b)
{
    int a_maj, a_min, a_pat, a_bld;
    int b_maj, b_min, b_pat, b_bld;

    if (parse_version(a, &a_maj, &a_min, &a_pat, &a_bld) != 0) return -1;
    if (parse_version(b, &b_maj, &b_min, &b_pat, &b_bld) != 0) return 1;

    if (a_maj != b_maj) return a_maj - b_maj;
    if (a_min != b_min) return a_min - b_min;
    if (a_pat != b_pat) return a_pat - b_pat;
    return a_bld - b_bld;
}

/*
 * Fetch URL content using curl (simple subprocess approach)
 */
static int fetch_url(const char *url, char *buf, size_t bufsize)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* Child: run curl */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        close(STDERR_FILENO);

        execlp("curl", "curl", "-s", "-L", "--max-time", "30",
               "-A", "Mozilla/5.0", url, NULL);
        _exit(1);
    }

    /* Parent: read output */
    close(pipefd[1]);

    size_t total = 0;
    ssize_t n;
    while (total < bufsize - 1 &&
           (n = read(pipefd[0], buf + total, bufsize - 1 - total)) > 0) {
        total += n;
    }
    buf[total] = '\0';
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/*
 * Extract version from APKPure HTML
 * Looks for pattern like: "Version: 2.26.3.79"
 */
static int extract_apkpure_version(const char *html, char *version, size_t size)
{
    /* Look for version pattern in various formats */
    const char *patterns[] = {
        "\"softwareVersion\":\"",
        "Version:</span> ",
        "versionName\">",
        "version: ",
        NULL
    };

    for (int i = 0; patterns[i]; i++) {
        const char *p = strstr(html, patterns[i]);
        if (p) {
            p += strlen(patterns[i]);

            /* Extract version number */
            int j = 0;
            while (j < (int)size - 1 &&
                   ((*p >= '0' && *p <= '9') || *p == '.')) {
                version[j++] = *p++;
            }
            version[j] = '\0';

            /* Validate */
            int maj, min, pat, bld;
            if (parse_version(version, &maj, &min, &pat, &bld) == 0) {
                return 0;
            }
        }
    }

    return -1;
}

/*
 * Fetch latest version from APKPure
 */
static int fetch_version_apkpure(char *version, size_t size)
{
    char *html = malloc(512 * 1024);  /* 512KB buffer */
    if (!html) return -1;

    int ret = -1;
    if (fetch_url(APKPURE_URL, html, 512 * 1024) == 0) {
        ret = extract_apkpure_version(html, version, size);
    }

    free(html);
    return ret;
}

/*
 * Check and update WhatsApp version
 */
int wa_version_check_update(void *store_ptr, char *current, size_t current_size)
{
    wa_store_t *store = store_ptr;
    char new_version[32] = {0};
    char last_check[32] = {0};

    /* Check if we checked recently */
    if (wa_store_config_get(store, "last_version_check", last_check, sizeof(last_check)) == 0) {
        time_t last = atol(last_check);
        if (time(NULL) - last < VERSION_CHECK_INTERVAL) {
            printf("Version check skipped (checked recently)\n");
            return 0;
        }
    }

    printf("Checking for WhatsApp version update...\n");

    /* Try APKPure first */
    if (fetch_version_apkpure(new_version, sizeof(new_version)) == 0) {
        printf("Found version: %s\n", new_version);

        /* Compare with current */
        if (compare_versions(new_version, current) > 0) {
            printf("Updating from %s to %s\n", current, new_version);
            wa_store_config_set(store, "whatsapp_version", new_version);
            strncpy(current, new_version, current_size - 1);
        } else {
            printf("Already at latest version: %s\n", current);
        }
    } else {
        printf("Could not fetch version, keeping: %s\n", current);
    }

    /* Update last check time */
    char now_str[32];
    snprintf(now_str, sizeof(now_str), "%ld", (long)time(NULL));
    wa_store_config_set(store, "last_version_check", now_str);

    return 0;
}

/*
 * Build user-agent string
 */
int wa_build_user_agent(const char *version, char *ua, size_t size)
{
    /* Format: WhatsApp/2.26.3.79 Android/14 Device/Google_Pixel_8 */
    snprintf(ua, size, "WhatsApp/%s Android/14 Device/Google_Pixel_8", version);
    return 0;
}

/*
 * CLI: Force version update check
 */
int wa_do_version_update(void *store_ptr, char *version, size_t size)
{
    /* Clear last check time to force update */
    wa_store_config_set(store_ptr, "last_version_check", "0");
    return wa_version_check_update(store_ptr, version, size);
}
