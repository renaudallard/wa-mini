/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Protobuf Message Structures
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 */

#ifndef WA_PROTO_H
#define WA_PROTO_H

#include <stdint.h>
#include <stddef.h>

/*
 * Protobuf wire types
 */
#define WIRE_VARINT  0
#define WIRE_64BIT   1
#define WIRE_BYTES   2
#define WIRE_32BIT   5

/*
 * Client payload structures for handshake
 * These map to the protobuf messages used in Noise handshake
 */

/* ClientHello message */
typedef struct {
    uint8_t *ephemeral;
    size_t ephemeral_len;

    uint8_t *static_encrypted;
    size_t static_len;

    uint8_t *payload_encrypted;
    size_t payload_len;

    int use_extended;
    uint8_t *extended_ciphertext;
    size_t extended_len;
} proto_client_hello_t;

/* ServerHello message */
typedef struct {
    uint8_t *ephemeral;
    size_t ephemeral_len;

    uint8_t *static_encrypted;
    size_t static_len;

    uint8_t *payload_encrypted;
    size_t payload_len;

    uint8_t *extended_static;
    size_t extended_static_len;
} proto_server_hello_t;

/* ClientFinish message */
typedef struct {
    uint8_t *static_encrypted;
    size_t static_len;

    uint8_t *payload_encrypted;
    size_t payload_len;

    uint8_t *extended_ciphertext;
    size_t extended_len;
} proto_client_finish_t;

/* HandshakeMessage wrapper */
typedef struct {
    int has_client_hello;
    proto_client_hello_t client_hello;

    int has_server_hello;
    proto_server_hello_t server_hello;

    int has_client_finish;
    proto_client_finish_t client_finish;
} proto_handshake_message_t;

/* App version structure */
typedef struct {
    uint32_t primary;
    uint32_t secondary;
    uint32_t tertiary;
    uint32_t quaternary;
} proto_app_version_t;

/* Device pairing data (Signal keys) */
typedef struct {
    uint8_t registration_id[4];     /* Big-endian 4 bytes */
    uint8_t key_type;               /* 0x05 = DJB type */
    uint8_t identity_pub[32];       /* Signal identity public key */
    uint8_t signed_prekey_id[4];    /* Big-endian 4 bytes */
    uint8_t signed_prekey_pub[32];  /* Signed prekey public */
    uint8_t signed_prekey_sig[64];  /* Signed prekey signature */
} proto_device_pairing_t;

/* Client payload for authentication */
typedef struct {
    uint64_t username;              /* Phone number as integer */

    int has_passive;
    int passive;

    uint8_t *push_name;
    size_t push_name_len;

    int has_session_id;
    uint32_t session_id;

    int has_short_connect;
    int short_connect;

    /* Device props */
    char *os_version;
    char *manufacturer;
    char *device_model;
    char *os_build_number;
    int platform_type;

    /* App version */
    int has_app_version;
    proto_app_version_t app_version;

    /* Device pairing data (Signal keys) */
    int has_device_pairing;
    proto_device_pairing_t device_pairing;
} proto_client_payload_t;

/* Signal identity key structure */
typedef struct {
    uint8_t identity_pub[32];
    uint8_t signed_prekey_pub[32];
    uint8_t signed_prekey_sig[64];
    uint32_t signed_prekey_id;
    uint32_t registration_id;
} proto_identity_t;

/* Registration request */
typedef struct {
    char *phone_number;
    char *method;                   /* "sms" or "voice" */
    char *lg;                       /* Language code */
    char *lc;                       /* Locale code */
    uint8_t *push_token;
    size_t push_token_len;
} proto_register_request_t;

/* Registration response */
typedef struct {
    int success;
    char *error_code;
    char *error_reason;
    int retry_after;
} proto_register_response_t;

/* Verification request */
typedef struct {
    char *phone_number;
    char *code;
} proto_verify_request_t;

/* Companion linking - primary identity */
typedef struct {
    uint8_t identity_pub[32];
    uint8_t signed_prekey_pub[32];
    uint8_t signed_prekey_sig[64];
    uint32_t signed_prekey_id;
    uint32_t device_id;
    uint8_t account_sig[64];
    uint8_t account_sig_key[32];
} proto_companion_identity_t;

/* Link code cryptography data */
typedef struct {
    uint8_t ephemeral_pub[32];
    uint8_t nonce[12];
    char ref[64];
} proto_link_hello_t;

/* Encode functions */
int proto_encode_client_hello(const proto_client_hello_t *msg, uint8_t *out, size_t *out_len);
int proto_encode_client_finish(const proto_client_finish_t *msg, uint8_t *out, size_t *out_len);
int proto_encode_handshake(const proto_handshake_message_t *msg, uint8_t *out, size_t *out_len);
int proto_encode_client_payload(const proto_client_payload_t *msg, uint8_t *out, size_t *out_len);
int proto_encode_identity(const proto_identity_t *id, uint8_t *out, size_t *out_len);

/* Decode functions */
int proto_decode_server_hello(const uint8_t *data, size_t len, proto_server_hello_t *msg);
int proto_decode_handshake(const uint8_t *data, size_t len, proto_handshake_message_t *msg);
int proto_decode_register_response(const uint8_t *data, size_t len, proto_register_response_t *msg);

/* Free functions */
void proto_free_handshake(proto_handshake_message_t *msg);
void proto_free_client_payload(proto_client_payload_t *msg);
void proto_free_register_response(proto_register_response_t *msg);

#endif /* WA_PROTO_H */
