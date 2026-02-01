/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Flat File Credential Storage
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <libgen.h>
#include <fcntl.h>

#include "wa-mini.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

/* File format constants */
#define ACCOUNT_MAGIC   "WAMN"
#define PREKEY_MAGIC    "WAPK"
#define COMPANION_MAGIC "WACO"
#define FORMAT_VERSION  1

/* File sizes */
#define ACCOUNT_FILE_SIZE   312
#define PREKEY_ENTRY_SIZE   36   /* 4 bytes key_id + 32 bytes key_data */
#define COMPANION_ENTRY_SIZE 136

/* Store context - tracks directory paths only */
typedef struct {
    char *data_dir;
    char *accounts_dir;
} wa_store_t;

/* CRC32 implementation (IEEE polynomial) */
static uint32_t crc32_table[256];
static int crc32_initialized = 0;

static void crc32_init(void)
{
    if (crc32_initialized) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
        crc32_table[i] = crc;
    }
    crc32_initialized = 1;
}

static uint32_t crc32(const void *data, size_t len)
{
    crc32_init();
    const uint8_t *buf = data;
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}

/* Little-endian helpers */
static void write_le32(uint8_t *buf, uint32_t val)
{
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF;
    buf[3] = (val >> 24) & 0xFF;
}

static uint32_t read_le32(const uint8_t *buf)
{
    return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

static void write_le64(uint8_t *buf, int64_t val)
{
    uint64_t uval = (uint64_t)val;
    buf[0] = uval & 0xFF;
    buf[1] = (uval >> 8) & 0xFF;
    buf[2] = (uval >> 16) & 0xFF;
    buf[3] = (uval >> 24) & 0xFF;
    buf[4] = (uval >> 32) & 0xFF;
    buf[5] = (uval >> 40) & 0xFF;
    buf[6] = (uval >> 48) & 0xFF;
    buf[7] = (uval >> 56) & 0xFF;
}

static int64_t read_le64(const uint8_t *buf)
{
    uint64_t val = buf[0] |
                   ((uint64_t)buf[1] << 8) |
                   ((uint64_t)buf[2] << 16) |
                   ((uint64_t)buf[3] << 24) |
                   ((uint64_t)buf[4] << 32) |
                   ((uint64_t)buf[5] << 40) |
                   ((uint64_t)buf[6] << 48) |
                   ((uint64_t)buf[7] << 56);
    return (int64_t)val;
}

/* Create directory if it doesn't exist */
static int ensure_directory(const char *path)
{
    struct stat st;

    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }
        return -1;  /* Exists but not a directory */
    }

    if (errno != ENOENT) {
        return -1;
    }

    /* Create directory with restricted permissions */
    if (mkdir(path, 0700) != 0) {
        return -1;
    }

    return 0;
}

/* Atomic write helper - writes to temp file then renames */
static int atomic_write(const char *path, const void *data, size_t len)
{
    char tmp[PATH_MAX];
    char dir[PATH_MAX];
    int fd = -1, dir_fd = -1;
    int ret = -1;

    /* Build temp path and get directory */
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, getpid());
    strncpy(dir, path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    char *parent = dirname(dir);

    /* Open directory for fsync */
    dir_fd = open(parent, O_RDONLY | O_DIRECTORY);
    if (dir_fd < 0) goto cleanup;

    /* Create temp file */
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) goto cleanup;

    /* Write data */
    ssize_t written = write(fd, data, len);
    if ((size_t)written != len) goto cleanup;

    /* Durability: sync file to disk */
    if (fsync(fd) < 0) goto cleanup;
    if (close(fd) < 0) { fd = -1; goto cleanup; }
    fd = -1;

    /* Atomicity: atomic rename */
    if (rename(tmp, path) < 0) goto cleanup;

    /* Durability: sync directory to persist rename */
    if (fsync(dir_fd) < 0) goto cleanup;

    ret = 0;

cleanup:
    if (fd >= 0) close(fd);
    if (dir_fd >= 0) close(dir_fd);
    if (ret < 0) unlink(tmp);
    return ret;
}

/* File locking */
static int lock_file(const char *path, int exclusive)
{
    int flags = exclusive ? O_RDWR : O_RDONLY;
    int fd = open(path, flags);
    if (fd < 0) return -1;

    int op = exclusive ? LOCK_EX : LOCK_SH;
    if (flock(fd, op) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void unlock_file(int fd)
{
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        close(fd);
    }
}

/*
 * Acquire exclusive lock for read-modify-write operations.
 * Uses a separate .lock file so we can lock even if data file doesn't exist.
 * Returns lock fd on success, -1 on failure.
 */
static int lock_for_modify(const char *data_path)
{
    char lock_path[PATH_MAX];
    snprintf(lock_path, sizeof(lock_path), "%s.lock", data_path);

    /* Create lock file if needed, then lock it */
    int fd = open(lock_path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) return -1;

    if (flock(fd, LOCK_EX) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Read file with shared lock */
static int read_with_lock(const char *path, void *buf, size_t len)
{
    int fd = lock_file(path, 0);  /* Shared lock */
    if (fd < 0) return -1;

    ssize_t n = read(fd, buf, len);
    unlock_file(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

/* Build path to account file */
static void build_account_path(wa_store_t *store, const char *phone,
                               const char *ext, char *path, size_t size)
{
    snprintf(path, size, "%s/%s%s", store->accounts_dir, phone, ext);
}

/* Open or create store */
wa_store_t *wa_store_open(const char *data_dir)
{
    WA_DEBUG("opening store in %s", data_dir);

    wa_store_t *store = calloc(1, sizeof(*store));
    if (store == NULL) return NULL;

    /* Ensure data directory exists */
    if (ensure_directory(data_dir) != 0) {
        fprintf(stderr, "Failed to create data directory: %s\n", data_dir);
        free(store);
        return NULL;
    }

    /* Store data directory path */
    store->data_dir = strdup(data_dir);
    if (store->data_dir == NULL) {
        free(store);
        return NULL;
    }

    /* Build and create accounts directory */
    size_t path_len = strlen(data_dir) + 16;
    store->accounts_dir = malloc(path_len);
    if (store->accounts_dir == NULL) {
        free(store->data_dir);
        free(store);
        return NULL;
    }
    snprintf(store->accounts_dir, path_len, "%s/accounts", data_dir);

    if (ensure_directory(store->accounts_dir) != 0) {
        fprintf(stderr, "Failed to create accounts directory: %s\n",
                store->accounts_dir);
        free(store->accounts_dir);
        free(store->data_dir);
        free(store);
        return NULL;
    }

    return store;
}

/* Close store */
void wa_store_close(wa_store_t *store)
{
    if (store == NULL) return;

    free(store->accounts_dir);
    free(store->data_dir);
    free(store);
}

/* Serialize account to binary buffer */
static void serialize_account(const wa_account_t *account, uint8_t *buf)
{
    memset(buf, 0, ACCOUNT_FILE_SIZE);

    /* Magic and version */
    memcpy(buf + 0, ACCOUNT_MAGIC, 4);
    buf[4] = FORMAT_VERSION;
    buf[5] = account->active ? 1 : 0;
    /* bytes 6-7 reserved */

    /* Phone (null-padded, 20 bytes) */
    size_t phone_len = strlen(account->phone);
    if (phone_len > 19) phone_len = 19;
    memcpy(buf + 8, account->phone, phone_len);

    /* Keys */
    memcpy(buf + 28, account->identity_key, 32);
    memcpy(buf + 60, account->identity_pub, 32);
    memcpy(buf + 92, account->signed_prekey, 32);
    memcpy(buf + 124, account->signed_prekey_sig, 64);

    /* IDs (little-endian) */
    write_le32(buf + 188, account->signed_prekey_id);
    write_le32(buf + 192, account->registration_id);

    /* Noise keys */
    memcpy(buf + 196, account->noise_static, 32);
    memcpy(buf + 228, account->noise_static_pub, 32);
    memcpy(buf + 260, account->server_static_pub, 32);

    /* Timestamp */
    write_le64(buf + 292, account->registered_at);
    /* bytes 300-307 reserved */

    /* CRC32 checksum */
    uint32_t checksum = crc32(buf, 308);
    write_le32(buf + 308, checksum);
}

/* Deserialize account from binary buffer */
static int deserialize_account(const uint8_t *buf, size_t len, wa_account_t *account)
{
    if (len != ACCOUNT_FILE_SIZE) return -1;

    /* Check magic */
    if (memcmp(buf, ACCOUNT_MAGIC, 4) != 0) return -1;

    /* Check version */
    if (buf[4] != FORMAT_VERSION) return -1;

    /* Verify checksum */
    uint32_t stored_crc = read_le32(buf + 308);
    uint32_t calc_crc = crc32(buf, 308);
    if (stored_crc != calc_crc) return -1;

    sodium_memzero(account, sizeof(*account));

    /* Active flag */
    account->active = buf[5] ? 1 : 0;

    /* Phone */
    memcpy(account->phone, buf + 8, 19);
    account->phone[19] = '\0';

    /* Keys */
    memcpy(account->identity_key, buf + 28, 32);
    memcpy(account->identity_pub, buf + 60, 32);
    memcpy(account->signed_prekey, buf + 92, 32);
    memcpy(account->signed_prekey_sig, buf + 124, 64);

    /* IDs */
    account->signed_prekey_id = read_le32(buf + 188);
    account->registration_id = read_le32(buf + 192);

    /* Noise keys */
    memcpy(account->noise_static, buf + 196, 32);
    memcpy(account->noise_static_pub, buf + 228, 32);
    memcpy(account->server_static_pub, buf + 260, 32);

    /* Timestamp */
    account->registered_at = read_le64(buf + 292);

    /* Generate pseudo-ID from phone hash for compatibility */
    account->id = (int64_t)crc32(account->phone, strlen(account->phone));

    return 0;
}

/* Save account */
int wa_store_account_save(wa_store_t *store, const wa_account_t *account)
{
    WA_DEBUG("saving account %s", account->phone);

    char path[PATH_MAX];
    uint8_t buf[ACCOUNT_FILE_SIZE];

    build_account_path(store, account->phone, ".acc", path, sizeof(path));
    serialize_account(account, buf);

    return atomic_write(path, buf, ACCOUNT_FILE_SIZE);
}

/* Load account by phone number */
int wa_store_account_load(wa_store_t *store, const char *phone, wa_account_t *account)
{
    WA_DEBUG("loading account %s", phone);

    char path[PATH_MAX];
    uint8_t buf[ACCOUNT_FILE_SIZE];

    build_account_path(store, phone, ".acc", path, sizeof(path));

    if (read_with_lock(path, buf, ACCOUNT_FILE_SIZE) != 0) {
        return -1;
    }

    return deserialize_account(buf, ACCOUNT_FILE_SIZE, account);
}

/* List all accounts */
int wa_store_account_list(wa_store_t *store, wa_account_t **accounts, int *count)
{
    DIR *dir = opendir(store->accounts_dir);
    if (dir == NULL) {
        *accounts = NULL;
        *count = 0;
        return 0;  /* No accounts directory = no accounts */
    }

    /* First pass: count .acc files */
    int n = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t len = strlen(entry->d_name);
        if (len > 4 && strcmp(entry->d_name + len - 4, ".acc") == 0) {
            n++;
        }
    }

    if (n == 0) {
        closedir(dir);
        *accounts = NULL;
        *count = 0;
        return 0;
    }

    /* Allocate array */
    *accounts = calloc(n, sizeof(wa_account_t));
    if (*accounts == NULL) {
        closedir(dir);
        return -1;
    }

    /* Second pass: load accounts */
    rewinddir(dir);
    int i = 0;
    while ((entry = readdir(dir)) != NULL && i < n) {
        size_t len = strlen(entry->d_name);
        if (len > 4 && strcmp(entry->d_name + len - 4, ".acc") == 0) {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", store->accounts_dir, entry->d_name);

            uint8_t buf[ACCOUNT_FILE_SIZE];
            if (read_with_lock(path, buf, ACCOUNT_FILE_SIZE) == 0) {
                if (deserialize_account(buf, ACCOUNT_FILE_SIZE, &(*accounts)[i]) == 0) {
                    i++;
                }
            }
        }
    }

    closedir(dir);
    *count = i;
    return 0;
}

/* Delete account */
int wa_store_account_delete(wa_store_t *store, const char *phone)
{
    WA_DEBUG("deleting account %s", phone);

    char path[PATH_MAX];
    int deleted = 0;

    /* Delete .acc file */
    build_account_path(store, phone, ".acc", path, sizeof(path));
    if (unlink(path) == 0) deleted = 1;

    /* Delete .prekeys file and its lock file */
    build_account_path(store, phone, ".prekeys", path, sizeof(path));
    unlink(path);  /* Ignore errors */
    build_account_path(store, phone, ".prekeys.lock", path, sizeof(path));
    unlink(path);  /* Ignore errors */

    /* Delete .companions file and its lock file */
    build_account_path(store, phone, ".companions", path, sizeof(path));
    unlink(path);  /* Ignore errors */
    build_account_path(store, phone, ".companions.lock", path, sizeof(path));
    unlink(path);  /* Ignore errors */

    return deleted ? 0 : -1;
}

/* Save prekey */
int wa_store_prekey_save(wa_store_t *store, int64_t account_id,
                         uint32_t key_id, const uint8_t *key_data)
{
    /* Find account by ID to get phone number */
    wa_account_t *accounts = NULL;
    int count = 0;
    if (wa_store_account_list(store, &accounts, &count) != 0 || count == 0) {
        return -1;
    }

    const char *phone = NULL;
    for (int i = 0; i < count; i++) {
        if (accounts[i].id == account_id) {
            phone = accounts[i].phone;
            break;
        }
    }

    if (phone == NULL) {
        free(accounts);
        return -1;
    }

    char path[PATH_MAX];
    build_account_path(store, phone, ".prekeys", path, sizeof(path));

    /* Acquire exclusive lock for entire read-modify-write cycle */
    int lock_fd = lock_for_modify(path);
    if (lock_fd < 0) {
        free(accounts);
        return -1;
    }

    /* Read existing prekeys file or create new */
    uint8_t *data = NULL;
    size_t data_size = 0;
    uint32_t existing_count = 0;
    int ret = -1;

    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_size >= 12) {
            data = malloc(st.st_size);
            if (data && read(fd, data, st.st_size) == st.st_size) {
                /* Validate header */
                if (memcmp(data, PREKEY_MAGIC, 4) == 0) {
                    existing_count = read_le32(data + 4);
                    data_size = st.st_size;

                    /* Verify checksum */
                    uint32_t stored_crc = read_le32(data + data_size - 4);
                    uint32_t calc_crc = crc32(data, data_size - 4);
                    if (stored_crc != calc_crc) {
                        /* Invalid file, start fresh */
                        free(data);
                        data = NULL;
                        existing_count = 0;
                    }
                } else {
                    free(data);
                    data = NULL;
                }
            } else {
                free(data);
                data = NULL;
            }
        }
        close(fd);
    }

    /* Check if key already exists */
    if (data != NULL) {
        for (uint32_t i = 0; i < existing_count; i++) {
            uint32_t existing_key_id = read_le32(data + 8 + i * PREKEY_ENTRY_SIZE);
            if (existing_key_id == key_id) {
                /* Update existing key */
                memcpy(data + 8 + i * PREKEY_ENTRY_SIZE + 4, key_data, 32);

                /* Recalculate checksum */
                uint32_t new_crc = crc32(data, data_size - 4);
                write_le32(data + data_size - 4, new_crc);

                ret = atomic_write(path, data, data_size);
                free(data);
                free(accounts);
                unlock_file(lock_fd);
                return ret;
            }
        }
    }

    /* Add new key */
    size_t new_size = 8 + (existing_count + 1) * PREKEY_ENTRY_SIZE + 4;
    uint8_t *new_data = malloc(new_size);
    if (new_data == NULL) {
        free(data);
        free(accounts);
        unlock_file(lock_fd);
        return -1;
    }

    /* Copy existing data or create header */
    if (data != NULL && existing_count > 0) {
        memcpy(new_data, data, 8 + existing_count * PREKEY_ENTRY_SIZE);
    } else {
        memcpy(new_data, PREKEY_MAGIC, 4);
    }
    write_le32(new_data + 4, existing_count + 1);

    /* Add new entry */
    size_t entry_offset = 8 + existing_count * PREKEY_ENTRY_SIZE;
    write_le32(new_data + entry_offset, key_id);
    memcpy(new_data + entry_offset + 4, key_data, 32);

    /* Calculate checksum */
    uint32_t new_crc = crc32(new_data, new_size - 4);
    write_le32(new_data + new_size - 4, new_crc);

    ret = atomic_write(path, new_data, new_size);

    free(new_data);
    free(data);
    free(accounts);
    unlock_file(lock_fd);
    return ret;
}

/* Mark prekey as used (remove from pool) */
int wa_store_prekey_mark_used(wa_store_t *store, int64_t account_id, uint32_t key_id)
{
    /* Find account by ID to get phone number */
    wa_account_t *accounts = NULL;
    int count = 0;
    if (wa_store_account_list(store, &accounts, &count) != 0 || count == 0) {
        return -1;
    }

    const char *phone = NULL;
    for (int i = 0; i < count; i++) {
        if (accounts[i].id == account_id) {
            phone = accounts[i].phone;
            break;
        }
    }

    if (phone == NULL) {
        free(accounts);
        return -1;
    }

    char path[PATH_MAX];
    build_account_path(store, phone, ".prekeys", path, sizeof(path));

    /* Acquire exclusive lock for entire read-modify-write cycle */
    int lock_fd = lock_for_modify(path);
    if (lock_fd < 0) {
        free(accounts);
        return -1;
    }

    /* Read prekeys file */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 12) {
        close(fd);
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }

    uint8_t *data = malloc(st.st_size);
    if (data == NULL) {
        close(fd);
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }

    if (read(fd, data, st.st_size) != st.st_size) {
        close(fd);
        free(data);
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }
    close(fd);

    /* Validate header and checksum */
    if (memcmp(data, PREKEY_MAGIC, 4) != 0) {
        free(data);
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }

    uint32_t existing_count = read_le32(data + 4);
    uint32_t stored_crc = read_le32(data + st.st_size - 4);
    uint32_t calc_crc = crc32(data, st.st_size - 4);
    if (stored_crc != calc_crc) {
        free(data);
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }

    /* Find and remove the key */
    int found = -1;
    for (uint32_t i = 0; i < existing_count; i++) {
        uint32_t existing_key_id = read_le32(data + 8 + i * PREKEY_ENTRY_SIZE);
        if (existing_key_id == key_id) {
            found = (int)i;
            break;
        }
    }

    if (found < 0) {
        free(data);
        unlock_file(lock_fd);
        free(accounts);
        return -1;  /* Key not found */
    }

    /* Create new data without the removed key */
    if (existing_count == 1) {
        /* Last key, delete the file */
        unlink(path);
        free(data);
        unlock_file(lock_fd);
        free(accounts);
        return 0;
    }

    size_t new_size = 8 + (existing_count - 1) * PREKEY_ENTRY_SIZE + 4;
    uint8_t *new_data = malloc(new_size);
    if (new_data == NULL) {
        free(data);
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }

    /* Copy header with decremented count */
    memcpy(new_data, PREKEY_MAGIC, 4);
    write_le32(new_data + 4, existing_count - 1);

    /* Copy entries, skipping the removed one */
    size_t dst_offset = 8;
    for (uint32_t i = 0; i < existing_count; i++) {
        if ((int)i != found) {
            memcpy(new_data + dst_offset, data + 8 + i * PREKEY_ENTRY_SIZE,
                   PREKEY_ENTRY_SIZE);
            dst_offset += PREKEY_ENTRY_SIZE;
        }
    }

    /* Calculate checksum */
    uint32_t new_crc = crc32(new_data, new_size - 4);
    write_le32(new_data + new_size - 4, new_crc);

    int ret = atomic_write(path, new_data, new_size);

    free(new_data);
    free(data);
    unlock_file(lock_fd);
    free(accounts);
    return ret;
}

/* Count unused prekeys */
int wa_store_prekey_count(wa_store_t *store, int64_t account_id)
{
    /* Find account by ID to get phone number */
    wa_account_t *accounts = NULL;
    int count = 0;
    if (wa_store_account_list(store, &accounts, &count) != 0 || count == 0) {
        return 0;
    }

    const char *phone = NULL;
    for (int i = 0; i < count; i++) {
        if (accounts[i].id == account_id) {
            phone = accounts[i].phone;
            break;
        }
    }

    if (phone == NULL) {
        free(accounts);
        return 0;
    }

    char path[PATH_MAX];
    build_account_path(store, phone, ".prekeys", path, sizeof(path));

    /* Read header to get count */
    uint8_t header[8];
    if (read_with_lock(path, header, 8) != 0) {
        free(accounts);
        return 0;
    }

    if (memcmp(header, PREKEY_MAGIC, 4) != 0) {
        free(accounts);
        return 0;
    }

    int prekey_count = (int)read_le32(header + 4);
    free(accounts);
    return prekey_count;
}

/* Serialize companion to buffer */
static void serialize_companion(const wa_companion_t *companion, uint8_t *buf)
{
    memset(buf, 0, COMPANION_ENTRY_SIZE);

    write_le32(buf + 0, companion->device_id);
    memcpy(buf + 4, companion->identity_pub, 32);

    size_t name_len = strlen(companion->name);
    if (name_len > 31) name_len = 31;
    memcpy(buf + 36, companion->name, name_len);

    size_t platform_len = strlen(companion->platform);
    if (platform_len > 31) platform_len = 31;
    memcpy(buf + 68, companion->platform, platform_len);

    write_le64(buf + 100, companion->linked_at);
    /* bytes 108-135 reserved */
}

/* Deserialize companion from buffer */
static void deserialize_companion(const uint8_t *buf, wa_companion_t *companion,
                                  int64_t account_id)
{
    sodium_memzero(companion, sizeof(*companion));

    companion->device_id = read_le32(buf + 0);
    memcpy(companion->identity_pub, buf + 4, 32);
    memcpy(companion->name, buf + 36, 31);
    companion->name[31] = '\0';
    memcpy(companion->platform, buf + 68, 31);
    companion->platform[31] = '\0';
    companion->linked_at = read_le64(buf + 100);
    companion->account_id = account_id;

    /* Generate pseudo-ID from device_id and account_id */
    companion->id = (account_id << 16) | companion->device_id;
}

/* Save companion device */
int wa_store_companion_save(wa_store_t *store, int64_t account_id,
                            const wa_companion_t *companion)
{
    /* Find account by ID to get phone number */
    wa_account_t *accounts = NULL;
    int count = 0;
    if (wa_store_account_list(store, &accounts, &count) != 0 || count == 0) {
        return -1;
    }

    const char *phone = NULL;
    for (int i = 0; i < count; i++) {
        if (accounts[i].id == account_id) {
            phone = accounts[i].phone;
            break;
        }
    }

    if (phone == NULL) {
        free(accounts);
        return -1;
    }

    char path[PATH_MAX];
    build_account_path(store, phone, ".companions", path, sizeof(path));

    /* Acquire exclusive lock for entire read-modify-write cycle */
    int lock_fd = lock_for_modify(path);
    if (lock_fd < 0) {
        free(accounts);
        return -1;
    }

    /* Read existing companions file or create new */
    uint8_t *data = NULL;
    size_t data_size = 0;
    uint32_t existing_count = 0;
    int ret = -1;

    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_size >= 12) {
            data = malloc(st.st_size);
            if (data && read(fd, data, st.st_size) == st.st_size) {
                /* Validate header */
                if (memcmp(data, COMPANION_MAGIC, 4) == 0) {
                    existing_count = read_le32(data + 4);
                    data_size = st.st_size;

                    /* Verify checksum */
                    uint32_t stored_crc = read_le32(data + data_size - 4);
                    uint32_t calc_crc = crc32(data, data_size - 4);
                    if (stored_crc != calc_crc) {
                        /* Invalid file, start fresh */
                        free(data);
                        data = NULL;
                        existing_count = 0;
                    }
                } else {
                    free(data);
                    data = NULL;
                }
            } else {
                free(data);
                data = NULL;
            }
        }
        close(fd);
    }

    /* Check if device_id already exists */
    if (data != NULL) {
        for (uint32_t i = 0; i < existing_count; i++) {
            uint32_t existing_device_id = read_le32(data + 8 + i * COMPANION_ENTRY_SIZE);
            if (existing_device_id == companion->device_id) {
                /* Update existing companion */
                serialize_companion(companion, data + 8 + i * COMPANION_ENTRY_SIZE);

                /* Recalculate checksum */
                uint32_t new_crc = crc32(data, data_size - 4);
                write_le32(data + data_size - 4, new_crc);

                ret = atomic_write(path, data, data_size);
                free(data);
                free(accounts);
                unlock_file(lock_fd);
                return ret;
            }
        }
    }

    /* Add new companion */
    size_t new_size = 8 + (existing_count + 1) * COMPANION_ENTRY_SIZE + 4;
    uint8_t *new_data = malloc(new_size);
    if (new_data == NULL) {
        free(data);
        free(accounts);
        unlock_file(lock_fd);
        return -1;
    }

    /* Copy existing data or create header */
    if (data != NULL && existing_count > 0) {
        memcpy(new_data, data, 8 + existing_count * COMPANION_ENTRY_SIZE);
    } else {
        memcpy(new_data, COMPANION_MAGIC, 4);
    }
    write_le32(new_data + 4, existing_count + 1);

    /* Add new entry */
    size_t entry_offset = 8 + existing_count * COMPANION_ENTRY_SIZE;
    serialize_companion(companion, new_data + entry_offset);

    /* Calculate checksum */
    uint32_t new_crc = crc32(new_data, new_size - 4);
    write_le32(new_data + new_size - 4, new_crc);

    ret = atomic_write(path, new_data, new_size);

    free(new_data);
    free(data);
    free(accounts);
    unlock_file(lock_fd);
    return ret;
}

/* List companion devices */
int wa_store_companion_list(wa_store_t *store, int64_t account_id,
                            wa_companion_t **companions, int *count)
{
    /* Find account by ID to get phone number */
    wa_account_t *accounts = NULL;
    int acc_count = 0;
    if (wa_store_account_list(store, &accounts, &acc_count) != 0 || acc_count == 0) {
        *companions = NULL;
        *count = 0;
        return 0;
    }

    const char *phone = NULL;
    for (int i = 0; i < acc_count; i++) {
        if (accounts[i].id == account_id) {
            phone = accounts[i].phone;
            break;
        }
    }

    if (phone == NULL) {
        free(accounts);
        *companions = NULL;
        *count = 0;
        return 0;
    }

    char path[PATH_MAX];
    build_account_path(store, phone, ".companions", path, sizeof(path));

    /* Read companions file */
    int fd = lock_file(path, 0);  /* Shared lock */
    if (fd < 0) {
        free(accounts);
        *companions = NULL;
        *count = 0;
        return 0;  /* No companions file = no companions */
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 12) {
        unlock_file(fd);
        free(accounts);
        *companions = NULL;
        *count = 0;
        return 0;
    }

    uint8_t *data = malloc(st.st_size);
    if (data == NULL) {
        unlock_file(fd);
        free(accounts);
        return -1;
    }

    if (read(fd, data, st.st_size) != st.st_size) {
        unlock_file(fd);
        free(data);
        free(accounts);
        return -1;
    }
    unlock_file(fd);

    /* Validate header and checksum */
    if (memcmp(data, COMPANION_MAGIC, 4) != 0) {
        free(data);
        free(accounts);
        *companions = NULL;
        *count = 0;
        return 0;
    }

    uint32_t existing_count = read_le32(data + 4);
    uint32_t stored_crc = read_le32(data + st.st_size - 4);
    uint32_t calc_crc = crc32(data, st.st_size - 4);
    if (stored_crc != calc_crc) {
        free(data);
        free(accounts);
        *companions = NULL;
        *count = 0;
        return 0;
    }

    if (existing_count == 0) {
        free(data);
        free(accounts);
        *companions = NULL;
        *count = 0;
        return 0;
    }

    /* Allocate and fill companions array */
    *companions = calloc(existing_count, sizeof(wa_companion_t));
    if (*companions == NULL) {
        free(data);
        free(accounts);
        return -1;
    }

    for (uint32_t i = 0; i < existing_count; i++) {
        deserialize_companion(data + 8 + i * COMPANION_ENTRY_SIZE,
                              &(*companions)[i], account_id);
    }

    *count = (int)existing_count;

    free(data);
    free(accounts);
    return 0;
}

/* Delete companion device */
int wa_store_companion_delete(wa_store_t *store, int64_t account_id, uint32_t device_id)
{
    /* Find account by ID to get phone number */
    wa_account_t *accounts = NULL;
    int count = 0;
    if (wa_store_account_list(store, &accounts, &count) != 0 || count == 0) {
        return -1;
    }

    const char *phone = NULL;
    for (int i = 0; i < count; i++) {
        if (accounts[i].id == account_id) {
            phone = accounts[i].phone;
            break;
        }
    }

    if (phone == NULL) {
        free(accounts);
        return -1;
    }

    char path[PATH_MAX];
    build_account_path(store, phone, ".companions", path, sizeof(path));

    /* Acquire exclusive lock for entire read-modify-write cycle */
    int lock_fd = lock_for_modify(path);
    if (lock_fd < 0) {
        free(accounts);
        return -1;
    }

    /* Read companions file */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 12) {
        close(fd);
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }

    uint8_t *data = malloc(st.st_size);
    if (data == NULL) {
        close(fd);
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }

    if (read(fd, data, st.st_size) != st.st_size) {
        close(fd);
        free(data);
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }
    close(fd);

    /* Validate header and checksum */
    if (memcmp(data, COMPANION_MAGIC, 4) != 0) {
        free(data);
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }

    uint32_t existing_count = read_le32(data + 4);
    uint32_t stored_crc = read_le32(data + st.st_size - 4);
    uint32_t calc_crc = crc32(data, st.st_size - 4);
    if (stored_crc != calc_crc) {
        free(data);
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }

    /* Find the companion to delete */
    int found = -1;
    for (uint32_t i = 0; i < existing_count; i++) {
        uint32_t existing_device_id = read_le32(data + 8 + i * COMPANION_ENTRY_SIZE);
        if (existing_device_id == device_id) {
            found = (int)i;
            break;
        }
    }

    if (found < 0) {
        free(data);
        unlock_file(lock_fd);
        free(accounts);
        return -1;  /* Companion not found */
    }

    /* Create new data without the removed companion */
    if (existing_count == 1) {
        /* Last companion, delete the file */
        unlink(path);
        free(data);
        unlock_file(lock_fd);
        free(accounts);
        return 0;
    }

    size_t new_size = 8 + (existing_count - 1) * COMPANION_ENTRY_SIZE + 4;
    uint8_t *new_data = malloc(new_size);
    if (new_data == NULL) {
        free(data);
        unlock_file(lock_fd);
        free(accounts);
        return -1;
    }

    /* Copy header with decremented count */
    memcpy(new_data, COMPANION_MAGIC, 4);
    write_le32(new_data + 4, existing_count - 1);

    /* Copy entries, skipping the removed one */
    size_t dst_offset = 8;
    for (uint32_t i = 0; i < existing_count; i++) {
        if ((int)i != found) {
            memcpy(new_data + dst_offset, data + 8 + i * COMPANION_ENTRY_SIZE,
                   COMPANION_ENTRY_SIZE);
            dst_offset += COMPANION_ENTRY_SIZE;
        }
    }

    /* Calculate checksum */
    uint32_t new_crc = crc32(new_data, new_size - 4);
    write_le32(new_data + new_size - 4, new_crc);

    int ret = atomic_write(path, new_data, new_size);

    free(new_data);
    free(data);
    unlock_file(lock_fd);
    free(accounts);
    return ret;
}

/* Get config value */
int wa_store_config_get(wa_store_t *store, const char *key, char *value, size_t value_size)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/config", store->data_dir);

    FILE *fp = fopen(path, "r");
    if (fp == NULL) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[--len] = '\0';
        }

        /* Find key=value separator */
        char *eq = strchr(line, '=');
        if (eq == NULL) continue;

        *eq = '\0';
        if (strcmp(line, key) == 0) {
            strncpy(value, eq + 1, value_size - 1);
            value[value_size - 1] = '\0';
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

/* Set config value */
int wa_store_config_set(wa_store_t *store, const char *key, const char *value)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/config", store->data_dir);

    /* Read existing config into memory */
    char config[8192];
    size_t config_len = 0;
    int key_found = 0;

    FILE *fp = fopen(path, "r");
    if (fp != NULL) {
        char line[512];
        while (fgets(line, sizeof(line), fp) != NULL) {
            size_t len = strlen(line);
            char *eq = strchr(line, '=');

            if (eq != NULL) {
                /* Check if this is the key we're setting */
                size_t key_len = eq - line;
                if (key_len == strlen(key) && strncmp(line, key, key_len) == 0) {
                    /* Replace with new value */
                    int n = snprintf(config + config_len, sizeof(config) - config_len,
                                     "%s=%s\n", key, value);
                    if (n > 0) config_len += n;
                    key_found = 1;
                    continue;
                }
            }

            /* Copy line as-is */
            if (config_len + len < sizeof(config)) {
                memcpy(config + config_len, line, len);
                config_len += len;
            }
        }
        fclose(fp);
    }

    /* Append new key if not found */
    if (!key_found) {
        int n = snprintf(config + config_len, sizeof(config) - config_len,
                         "%s=%s\n", key, value);
        if (n > 0) config_len += n;
    }

    return atomic_write(path, config, config_len);
}
