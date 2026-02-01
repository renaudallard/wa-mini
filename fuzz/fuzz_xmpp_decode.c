/*
 * wa-mini - Fuzz harness for XMPP decoder
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "xmpp.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) return 0;

    size_t consumed = 0;
    xmpp_node_t *node = xmpp_decode(data, size, &consumed);

    if (node != NULL) {
        /* Exercise node accessors */
        (void)node->tag;
        (void)node->attr_count;
        (void)node->child_count;

        /* Try to get some attributes */
        (void)xmpp_node_get_attr(node, "id");
        (void)xmpp_node_get_attr(node, "type");
        (void)xmpp_node_get_attr(node, "xmlns");

        /* Try to find children */
        (void)xmpp_node_find_child(node, "query");
        (void)xmpp_node_find_child(node, "ping");

        /* Free the node */
        xmpp_node_free(node);
    }

    return 0;
}
