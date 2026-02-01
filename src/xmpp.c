/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Binary XMPP Encoder/Decoder
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "xmpp.h"
#include "dict.h"

/* Forward declarations for dict functions */
extern int dict_encode_token(const char *str, uint8_t *out, size_t out_size);
extern const char *dict_decode_token(const uint8_t *data, size_t len, size_t *consumed,
                                     int *needs_free);

/*
 * Node operations
 */

xmpp_node_t *xmpp_node_new(const char *tag)
{
    xmpp_node_t *node = calloc(1, sizeof(*node));
    if (node == NULL) return NULL;

    if (tag != NULL) {
        node->tag = strdup(tag);
        if (node->tag == NULL) {
            free(node);
            return NULL;
        }
    }

    return node;
}

/* Internal: free node contents but not the node struct itself */
static void xmpp_node_clear(xmpp_node_t *node)
{
    if (node == NULL) return;

    free(node->tag);
    node->tag = NULL;

    for (int i = 0; i < node->attr_count; i++) {
        free(node->attrs[i].name);
        free(node->attrs[i].value);
    }
    node->attr_count = 0;

    free(node->content);
    node->content = NULL;
    node->content_len = 0;

    /* Free children recursively (they are embedded structs, not pointers) */
    for (int i = 0; i < node->child_count; i++) {
        xmpp_node_clear(&node->children[i]);
    }
    free(node->children);
    node->children = NULL;
    node->child_count = 0;
    node->child_capacity = 0;
}

void xmpp_node_free(xmpp_node_t *node)
{
    if (node == NULL) return;

    xmpp_node_clear(node);
    free(node);
}

int xmpp_node_set_attr(xmpp_node_t *node, const char *name, const char *value)
{
    if (node->attr_count >= XMPP_MAX_ATTRS) {
        return -1;
    }

    /* Check if attribute already exists */
    for (int i = 0; i < node->attr_count; i++) {
        if (strcmp(node->attrs[i].name, name) == 0) {
            free(node->attrs[i].value);
            node->attrs[i].value = strdup(value);
            return node->attrs[i].value ? 0 : -1;
        }
    }

    node->attrs[node->attr_count].name = strdup(name);
    node->attrs[node->attr_count].value = strdup(value);

    if (node->attrs[node->attr_count].name == NULL ||
        node->attrs[node->attr_count].value == NULL) {
        free(node->attrs[node->attr_count].name);
        free(node->attrs[node->attr_count].value);
        return -1;
    }

    node->attr_count++;
    return 0;
}

const char *xmpp_node_get_attr(const xmpp_node_t *node, const char *name)
{
    for (int i = 0; i < node->attr_count; i++) {
        if (strcmp(node->attrs[i].name, name) == 0) {
            return node->attrs[i].value;
        }
    }
    return NULL;
}

int xmpp_node_set_content(xmpp_node_t *node, const uint8_t *data, size_t len)
{
    free(node->content);

    node->content = malloc(len);
    if (node->content == NULL) return -1;

    memcpy(node->content, data, len);
    node->content_len = len;
    return 0;
}

int xmpp_node_set_text(xmpp_node_t *node, const char *text)
{
    return xmpp_node_set_content(node, (const uint8_t *)text, strlen(text));
}

int xmpp_node_add_child(xmpp_node_t *parent, xmpp_node_t *child)
{
    if (parent->child_count >= parent->child_capacity) {
        int new_cap = parent->child_capacity == 0 ? 4 : parent->child_capacity * 2;
        xmpp_node_t *new_children = realloc(parent->children,
                                            new_cap * sizeof(xmpp_node_t));
        if (new_children == NULL) return -1;
        parent->children = new_children;
        parent->child_capacity = new_cap;
    }

    /* Copy child into array (shallow copy, we take ownership) */
    memcpy(&parent->children[parent->child_count], child, sizeof(xmpp_node_t));
    parent->child_count++;

    /* Clear the original to prevent double-free, but don't free it */
    memset(child, 0, sizeof(*child));

    return 0;
}

xmpp_node_t *xmpp_node_find_child(const xmpp_node_t *node, const char *tag)
{
    for (int i = 0; i < node->child_count; i++) {
        if (node->children[i].tag != NULL &&
            strcmp(node->children[i].tag, tag) == 0) {
            return &node->children[i];
        }
    }
    return NULL;
}

/*
 * Encoding
 */

/* Write list header */
static int write_list_start(uint8_t *out, size_t *pos, size_t out_size, int count)
{
    if (count == 0) {
        if (*pos >= out_size) return -1;
        out[(*pos)++] = DICT_LIST_EMPTY;
    } else if (count < 256) {
        if (*pos + 2 > out_size) return -1;
        out[(*pos)++] = DICT_LIST_8;
        out[(*pos)++] = (uint8_t)count;
    } else {
        if (*pos + 3 > out_size) return -1;
        out[(*pos)++] = DICT_LIST_16;
        out[(*pos)++] = (count >> 8) & 0xFF;
        out[(*pos)++] = count & 0xFF;
    }
    return 0;
}

/* Write a string token */
static int write_string(uint8_t *out, size_t *pos, size_t out_size, const char *str)
{
    if (str == NULL) {
        if (*pos >= out_size) return -1;
        out[(*pos)++] = DICT_LIST_EMPTY;  /* NULL string encoded as empty */
        return 0;
    }

    int ret = dict_encode_token(str, out + *pos, out_size - *pos);
    if (ret < 0) return -1;
    *pos += ret;
    return 0;
}

/* Write binary data */
static int write_binary(uint8_t *out, size_t *pos, size_t out_size,
                        const uint8_t *data, size_t len)
{
    if (len <= 0xFF) {
        if (*pos + 2 + len > out_size) return -1;
        out[(*pos)++] = DICT_BINARY_8;
        out[(*pos)++] = (uint8_t)len;
    } else if (len <= 0xFFFFF) {
        if (*pos + 4 + len > out_size) return -1;
        out[(*pos)++] = DICT_BINARY_20;
        out[(*pos)++] = (len >> 16) & 0x0F;   /* bits 19-16 */
        out[(*pos)++] = (len >> 8) & 0xFF;    /* bits 15-8 */
        out[(*pos)++] = len & 0xFF;           /* bits 7-0 */
    } else {
        if (*pos + 5 + len > out_size) return -1;
        out[(*pos)++] = DICT_BINARY_32;
        out[(*pos)++] = (len >> 24) & 0xFF;
        out[(*pos)++] = (len >> 16) & 0xFF;
        out[(*pos)++] = (len >> 8) & 0xFF;
        out[(*pos)++] = len & 0xFF;
    }

    memcpy(out + *pos, data, len);
    *pos += len;
    return 0;
}

/* Encode node recursively */
static int encode_node(const xmpp_node_t *node, uint8_t *out, size_t *pos, size_t out_size)
{
    /* Calculate list size: 1 (tag) + 2*attrs + children/content */
    int list_size = 1 + 2 * node->attr_count;
    if (node->content_len > 0) {
        list_size++;
    } else if (node->child_count > 0) {
        list_size++;
    }

    /* Write list header */
    if (write_list_start(out, pos, out_size, list_size) < 0) {
        return -1;
    }

    /* Write tag */
    if (write_string(out, pos, out_size, node->tag) < 0) {
        return -1;
    }

    /* Write attributes */
    for (int i = 0; i < node->attr_count; i++) {
        if (write_string(out, pos, out_size, node->attrs[i].name) < 0) {
            return -1;
        }
        if (write_string(out, pos, out_size, node->attrs[i].value) < 0) {
            return -1;
        }
    }

    /* Write content or children */
    if (node->content_len > 0) {
        if (write_binary(out, pos, out_size, node->content, node->content_len) < 0) {
            return -1;
        }
    } else if (node->child_count > 0) {
        /* Write children as a list */
        if (write_list_start(out, pos, out_size, node->child_count) < 0) {
            return -1;
        }

        for (int i = 0; i < node->child_count; i++) {
            if (encode_node(&node->children[i], out, pos, out_size) < 0) {
                return -1;
            }
        }
    }

    return 0;
}

int xmpp_encode(const xmpp_node_t *node, uint8_t *out, size_t *out_len)
{
    size_t pos = 0;

    if (encode_node(node, out, &pos, XMPP_MAX_ENCODED) < 0) {
        return -1;
    }

    *out_len = pos;
    return 0;
}

/*
 * Decoding
 */

/* Read a byte */
static int read_byte(const uint8_t *data, size_t len, size_t *pos, uint8_t *out)
{
    if (*pos >= len) return -1;
    *out = data[(*pos)++];
    return 0;
}

/* Read list header, return count */
static int read_list_size(const uint8_t *data, size_t len, size_t *pos)
{
    uint8_t byte;
    if (read_byte(data, len, pos, &byte) < 0) return -1;

    if (byte == DICT_LIST_EMPTY) {
        return 0;
    } else if (byte == DICT_LIST_8) {
        if (read_byte(data, len, pos, &byte) < 0) return -1;
        return byte;
    } else if (byte == DICT_LIST_16) {
        uint8_t hi, lo;
        if (read_byte(data, len, pos, &hi) < 0) return -1;
        if (read_byte(data, len, pos, &lo) < 0) return -1;
        return (hi << 8) | lo;
    }

    /* Not a list - back up */
    (*pos)--;
    return -1;
}

/* Peek at next byte */
static int peek_byte(const uint8_t *data, size_t len, size_t pos)
{
    if (pos >= len) return -1;
    return data[pos];
}

/* Read a string token */
static char *read_string(const uint8_t *data, size_t len, size_t *pos)
{
    size_t consumed = 0;
    int needs_free = 0;

    const char *str = dict_decode_token(data + *pos, len - *pos, &consumed, &needs_free);
    if (str == NULL) return NULL;

    *pos += consumed;

    if (needs_free) {
        return (char *)str;  /* Already allocated */
    } else {
        return strdup(str);  /* Need to copy from dictionary */
    }
}

/* Read binary data */
static uint8_t *read_binary(const uint8_t *data, size_t len, size_t *pos, size_t *out_len)
{
    uint8_t byte;
    if (read_byte(data, len, pos, &byte) < 0) return NULL;

    size_t dlen = 0;

    if (byte == DICT_BINARY_8) {
        if (read_byte(data, len, pos, &byte) < 0) return NULL;
        dlen = byte;
    } else if (byte == DICT_BINARY_20) {
        uint8_t b0, b1, b2;
        if (read_byte(data, len, pos, &b0) < 0) return NULL;
        if (read_byte(data, len, pos, &b1) < 0) return NULL;
        if (read_byte(data, len, pos, &b2) < 0) return NULL;
        dlen = ((size_t)(b0 & 0x0F) << 16) | ((size_t)b1 << 8) | b2;
    } else if (byte == DICT_BINARY_32) {
        uint8_t b1, b2, b3, b4;
        if (read_byte(data, len, pos, &b1) < 0) return NULL;
        if (read_byte(data, len, pos, &b2) < 0) return NULL;
        if (read_byte(data, len, pos, &b3) < 0) return NULL;
        if (read_byte(data, len, pos, &b4) < 0) return NULL;
        dlen = ((size_t)b1 << 24) | ((size_t)b2 << 16) | ((size_t)b3 << 8) | b4;
    } else {
        /* Not binary - back up */
        (*pos)--;
        return NULL;
    }

    if (*pos + dlen > len) return NULL;

    uint8_t *out = malloc(dlen);
    if (out == NULL) return NULL;

    memcpy(out, data + *pos, dlen);
    *pos += dlen;
    *out_len = dlen;

    return out;
}

/* Forward declaration for recursive decoding */
static xmpp_node_t *decode_node(const uint8_t *data, size_t len, size_t *pos);

/* Decode node recursively */
static xmpp_node_t *decode_node(const uint8_t *data, size_t len, size_t *pos)
{
    int list_size = read_list_size(data, len, pos);
    if (list_size < 0) return NULL;
    if (list_size == 0) return NULL;  /* Empty node */

    xmpp_node_t *node = xmpp_node_new(NULL);
    if (node == NULL) return NULL;

    /* Read tag */
    node->tag = read_string(data, len, pos);
    if (node->tag == NULL) {
        xmpp_node_free(node);
        return NULL;
    }

    /* Remaining items are attributes (in pairs) and possibly content/children */
    int remaining = list_size - 1;

    /* Attributes come in pairs */
    while (remaining >= 2) {
        int next = peek_byte(data, len, *pos);
        if (next < 0) break;

        /* Check if this might be a list (children) or binary (content) */
        if (next == DICT_LIST_8 || next == DICT_LIST_16 ||
            next == DICT_BINARY_8 || next == DICT_BINARY_20 || next == DICT_BINARY_32) {
            break;  /* This is content or children, not attributes */
        }

        char *name = read_string(data, len, pos);
        if (name == NULL) break;

        char *value = read_string(data, len, pos);
        if (value == NULL) {
            free(name);
            break;
        }

        xmpp_node_set_attr(node, name, value);
        free(name);
        free(value);
        remaining -= 2;
    }

    /* Check for content or children */
    if (remaining > 0) {
        int next = peek_byte(data, len, *pos);

        if (next == DICT_LIST_8 || next == DICT_LIST_16 || next == DICT_LIST_EMPTY) {
            /* Children list */
            int child_count = read_list_size(data, len, pos);
            if (child_count > 0) {
                for (int i = 0; i < child_count; i++) {
                    xmpp_node_t *child = decode_node(data, len, pos);
                    if (child != NULL) {
                        xmpp_node_add_child(node, child);
                        free(child);  /* add_child copied it */
                    }
                }
            }
        } else if (next == DICT_BINARY_8 || next == DICT_BINARY_20 || next == DICT_BINARY_32) {
            /* Binary content */
            size_t content_len = 0;
            uint8_t *content = read_binary(data, len, pos, &content_len);
            if (content != NULL) {
                node->content = content;
                node->content_len = content_len;
            }
        } else {
            /* Text content - read as string */
            char *text = read_string(data, len, pos);
            if (text != NULL) {
                xmpp_node_set_text(node, text);
                free(text);
            }
        }
    }

    return node;
}

xmpp_node_t *xmpp_decode(const uint8_t *data, size_t len, size_t *consumed)
{
    size_t pos = 0;
    xmpp_node_t *node = decode_node(data, len, &pos);

    if (consumed != NULL) {
        *consumed = pos;
    }

    return node;
}

/*
 * Buffer operations
 */

xmpp_buffer_t *xmpp_buffer_new(size_t initial_capacity)
{
    xmpp_buffer_t *buf = calloc(1, sizeof(*buf));
    if (buf == NULL) return NULL;

    buf->data = malloc(initial_capacity);
    if (buf->data == NULL) {
        free(buf);
        return NULL;
    }

    buf->capacity = initial_capacity;
    return buf;
}

void xmpp_buffer_free(xmpp_buffer_t *buf)
{
    if (buf == NULL) return;
    free(buf->data);
    free(buf);
}

int xmpp_buffer_write(xmpp_buffer_t *buf, const uint8_t *data, size_t len)
{
    if (buf->len + len > buf->capacity) {
        size_t new_cap = buf->capacity * 2;
        if (new_cap < buf->len + len) {
            new_cap = buf->len + len;
        }

        uint8_t *new_data = realloc(buf->data, new_cap);
        if (new_data == NULL) return -1;

        buf->data = new_data;
        buf->capacity = new_cap;
    }

    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return 0;
}

int xmpp_buffer_read(xmpp_buffer_t *buf, uint8_t *data, size_t len)
{
    if (buf->pos + len > buf->len) return -1;

    memcpy(data, buf->data + buf->pos, len);
    buf->pos += len;
    return 0;
}

/*
 * Helper functions
 */

xmpp_node_t *xmpp_iq_new(const char *type, const char *id, const char *xmlns)
{
    xmpp_node_t *node = xmpp_node_new("iq");
    if (node == NULL) return NULL;

    if (type != NULL) xmpp_node_set_attr(node, "type", type);
    if (id != NULL) xmpp_node_set_attr(node, "id", id);
    if (xmlns != NULL) xmpp_node_set_attr(node, "xmlns", xmlns);

    return node;
}

xmpp_node_t *xmpp_presence_new(const char *type)
{
    xmpp_node_t *node = xmpp_node_new("presence");
    if (node == NULL) return NULL;

    if (type != NULL) {
        xmpp_node_set_attr(node, "type", type);
    }

    return node;
}

xmpp_node_t *xmpp_message_new(const char *to, const char *type)
{
    xmpp_node_t *node = xmpp_node_new("message");
    if (node == NULL) return NULL;

    if (to != NULL) xmpp_node_set_attr(node, "to", to);
    if (type != NULL) xmpp_node_set_attr(node, "type", type);

    return node;
}

void xmpp_node_dump(const xmpp_node_t *node, int indent)
{
    if (node == NULL) return;

    for (int i = 0; i < indent; i++) printf("  ");

    printf("<%s", node->tag ? node->tag : "(null)");

    for (int i = 0; i < node->attr_count; i++) {
        printf(" %s=\"%s\"", node->attrs[i].name, node->attrs[i].value);
    }

    if (node->content_len > 0) {
        printf(">");
        /* Try to print as text if printable */
        int printable = 1;
        for (size_t i = 0; i < node->content_len && i < 100; i++) {
            if (node->content[i] < 32 && node->content[i] != '\n' &&
                node->content[i] != '\r' && node->content[i] != '\t') {
                printable = 0;
                break;
            }
        }

        if (printable) {
            printf("%.*s", (int)node->content_len, node->content);
        } else {
            printf("[%zu bytes binary]", node->content_len);
        }
        printf("</%s>\n", node->tag ? node->tag : "(null)");
    } else if (node->child_count > 0) {
        printf(">\n");
        for (int i = 0; i < node->child_count; i++) {
            xmpp_node_dump(&node->children[i], indent + 1);
        }
        for (int i = 0; i < indent; i++) printf("  ");
        printf("</%s>\n", node->tag ? node->tag : "(null)");
    } else {
        printf("/>\n");
    }
}
