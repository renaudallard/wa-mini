/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Binary XMPP Types and Functions
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#ifndef WA_XMPP_H
#define WA_XMPP_H

#include <stdint.h>
#include <stddef.h>

/* Maximum sizes */
#define XMPP_MAX_ATTRS      32
#define XMPP_MAX_CHILDREN   64
#define XMPP_MAX_CONTENT    65536
#define XMPP_MAX_TAG_LEN    256
#define XMPP_MAX_ENCODED    131072

/* Attribute structure */
typedef struct {
    char *name;
    char *value;
} xmpp_attr_t;

/* XMPP node structure */
typedef struct xmpp_node {
    char *tag;
    xmpp_attr_t attrs[XMPP_MAX_ATTRS];
    int attr_count;

    uint8_t *content;
    size_t content_len;

    struct xmpp_node *children;
    int child_count;
    int child_capacity;

    struct xmpp_node *next;  /* For linked list in parser */
} xmpp_node_t;

/* Buffer for encoding/decoding */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t pos;
    size_t capacity;
} xmpp_buffer_t;

/* Create new node */
xmpp_node_t *xmpp_node_new(const char *tag);

/* Free node and all children */
void xmpp_node_free(xmpp_node_t *node);

/* Add attribute to node */
int xmpp_node_set_attr(xmpp_node_t *node, const char *name, const char *value);

/* Get attribute from node */
const char *xmpp_node_get_attr(const xmpp_node_t *node, const char *name);

/* Set binary content */
int xmpp_node_set_content(xmpp_node_t *node, const uint8_t *data, size_t len);

/* Set text content */
int xmpp_node_set_text(xmpp_node_t *node, const char *text);

/* Add child node */
int xmpp_node_add_child(xmpp_node_t *parent, xmpp_node_t *child);

/* Find child by tag */
xmpp_node_t *xmpp_node_find_child(const xmpp_node_t *node, const char *tag);

/* Encode node to binary XMPP */
int xmpp_encode(const xmpp_node_t *node, uint8_t *out, size_t *out_len);

/* Decode binary XMPP to node */
xmpp_node_t *xmpp_decode(const uint8_t *data, size_t len, size_t *consumed);

/* Buffer operations */
xmpp_buffer_t *xmpp_buffer_new(size_t initial_capacity);
void xmpp_buffer_free(xmpp_buffer_t *buf);
int xmpp_buffer_write(xmpp_buffer_t *buf, const uint8_t *data, size_t len);
int xmpp_buffer_read(xmpp_buffer_t *buf, uint8_t *data, size_t len);

/* Helper: Build IQ stanza */
xmpp_node_t *xmpp_iq_new(const char *type, const char *id, const char *xmlns);

/* Helper: Build presence stanza */
xmpp_node_t *xmpp_presence_new(const char *type);

/* Helper: Build message stanza */
xmpp_node_t *xmpp_message_new(const char *to, const char *type);

/* Debug: Print node tree */
void xmpp_node_dump(const xmpp_node_t *node, int indent);

#endif /* WA_XMPP_H */
