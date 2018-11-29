/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <s2n.h>

#include "error/s2n_errno.h"

#include "tls/s2n_kem.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_resume.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_dhe.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_pkey.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

static int calculate_keys(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_kex_tls_prf(kex, conn, shared_key));
    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(shared_key));
    if (shared_key->allocated) {
        GUARD(s2n_free(shared_key));
    }
    /* Expand the keys */
    GUARD(s2n_prf_key_expansion(conn));
    /* Save the master secret in the cache */
    if (s2n_allowed_to_cache_connection(conn)) {
        GUARD(s2n_store_to_cache(conn));
    }
    return 0;
}

int s2n_rsa_client_key_recv(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    uint16_t length;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        length = s2n_stuffer_data_available(in);
    } else {
        GUARD(s2n_stuffer_read_uint16(in, &length));
    }

    S2N_ERROR_IF(length > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    /* Keep a copy of the client protocol version in wire format */
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    /* Decrypt the pre-master secret */
    shared_key->data = conn->secure.rsa_premaster_secret;
    shared_key->size = S2N_TLS_SECRET_LEN;

    struct s2n_blob encrypted = {.size = length, .data = s2n_stuffer_raw_read(in, length)};
    notnull_check(encrypted.data);
    gt_check(encrypted.size, 0);

    /* First: use a random pre-master secret */
    GUARD(s2n_get_private_random_data(shared_key));
    conn->secure.rsa_premaster_secret[0] = client_protocol_version[0];
    conn->secure.rsa_premaster_secret[1] = client_protocol_version[1];

    /* Set rsa_failed to 1 if s2n_pkey_decrypt returns anything other than zero */
    conn->handshake.rsa_failed = !!s2n_pkey_decrypt(&conn->config->cert_and_key_pairs->private_key, &encrypted, shared_key);

    /* Set rsa_failed to 1, if it isn't already, if the protocol version isn't what we expect */
    conn->handshake.rsa_failed |= !s2n_constant_time_equals(client_protocol_version, shared_key->data, S2N_TLS_PROTOCOL_VERSION_LEN);
    return 0;
}

int s2n_dhe_client_key_recv(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    /* Get the shared key */
    GUARD(s2n_dh_compute_shared_secret_as_server(&conn->secure.server_dh_params, in, shared_key));
    /* We don't need the server params any more */
    GUARD(s2n_dh_params_free(&conn->secure.server_dh_params));
    return 0;
}

int s2n_ecdhe_client_key_recv(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    /* Get the shared key */
    GUARD(s2n_ecc_compute_shared_secret_as_server(&conn->secure.server_ecc_params, in, shared_key));
    /* We don't need the server params any more */
    GUARD(s2n_ecc_params_free(&conn->secure.server_ecc_params));
    return 0;
}

int s2n_client_key_recv(struct s2n_connection *conn)
{
    const struct s2n_kex *key_exchange = conn->secure.cipher_suite->key_exchange_alg;
    struct s2n_blob shared_key = {0};

    GUARD(s2n_kex_client_key_recv(key_exchange, conn, &shared_key));

    GUARD(calculate_keys(key_exchange, conn, &shared_key));
    return 0;
}

int s2n_dhe_client_key_send(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    GUARD(s2n_dh_compute_shared_secret_as_client(&conn->secure.server_dh_params, out, shared_key));

    /* We don't need the server params any more */
    GUARD(s2n_dh_params_free(&conn->secure.server_dh_params));
    return 0;
}

int s2n_ecdhe_client_key_send(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    GUARD(s2n_ecc_compute_shared_secret_as_client(&conn->secure.server_ecc_params, out, shared_key));

    /* We don't need the server params any more */
    GUARD(s2n_ecc_params_free(&conn->secure.server_ecc_params));
    return 0;
}

int s2n_rsa_client_key_send(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    shared_key->data = conn->secure.rsa_premaster_secret;
    shared_key->size = S2N_TLS_SECRET_LEN;

    GUARD(s2n_get_private_random_data(shared_key));

    /* Over-write the first two bytes with the client protocol version, per RFC2246 7.4.7.1 */
    memcpy_check(conn->secure.rsa_premaster_secret, client_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN);

    int encrypted_size = s2n_pkey_size(&conn->secure.server_public_key);
    S2N_ERROR_IF(encrypted_size < 0 || encrypted_size > 0xffff, S2N_ERR_SIZE_MISMATCH);

    if (conn->actual_protocol_version > S2N_SSLv3) {
        GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, encrypted_size));
    }

    struct s2n_blob encrypted = {0};
    encrypted.data = s2n_stuffer_raw_write(&conn->handshake.io, encrypted_size);
    encrypted.size = encrypted_size;
    notnull_check(encrypted.data);

    /* Encrypt the secret and send it on */
    GUARD(s2n_pkey_encrypt(&conn->secure.server_public_key, shared_key, &encrypted));

    /* We don't need the key any more, so free it */
    GUARD(s2n_pkey_free(&conn->secure.server_public_key));
    return 0;
}

int s2n_client_key_send(struct s2n_connection *conn)
{
    const struct s2n_kex *key_exchange = conn->secure.cipher_suite->key_exchange_alg;
    struct s2n_blob shared_key = {0};

    GUARD(s2n_kex_client_key_send(key_exchange, conn, &shared_key));

    GUARD(calculate_keys(key_exchange, conn, &shared_key));
    return 0;
}

int s2n_kem_client_recv_key(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    const struct s2n_kem *kem = conn->secure.kem_params.negotiated_kem;
    uint16_t ciphertext_length;

    GUARD(s2n_stuffer_read_uint16(in, &ciphertext_length));
    S2N_ERROR_IF(ciphertext_length > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);
    struct s2n_blob ciphertext = {.size = ciphertext_length, .data = s2n_stuffer_raw_read(in, ciphertext_length)};
    notnull_check(ciphertext.data);

    s2n_kem_decrypt_shared_secret(kem, &conn->secure.kem_params, shared_key, &ciphertext);

    GUARD(s2n_free(&conn->secure.kem_params.private_key));

    return 0;
}

int s2n_kem_client_send_key(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    const struct s2n_kem *kem = conn->secure.kem_params.negotiated_kem;

    struct s2n_blob ciphertext = {0};
    s2n_kem_generate_shared_secret(kem, &conn->secure.kem_params, shared_key, &ciphertext);


    GUARD(s2n_stuffer_write_uint16(out, ciphertext.size));
    GUARD(s2n_stuffer_write(out, &ciphertext));
    return 0;
}

int s2n_hybrid_client_recv_params(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *io = &conn->handshake.io;

    /* Keep a copy to the start of the entire hybrid client key exchange message for the hybrid PRF */
    struct s2n_blob *client_key_exchange_message = &conn->secure.client_key_exchange_message;
    client_key_exchange_message->data = s2n_stuffer_raw_read(io, 0);
    notnull_check(client_key_exchange_message->data);
    const int start = io->read_cursor;
    
    const struct s2n_kex *hybrid_kex_1 = *kex->hybrid;
    const struct s2n_kex *hybrid_kex_2 = hybrid_kex_1 + 1;
    
    struct s2n_blob shared_key_1 = {0}; // fix name
    GUARD(s2n_kex_client_key_recv(hybrid_kex_1, conn, &shared_key_1));

    struct s2n_blob shared_key_2 = {0};
    GUARD(s2n_kex_client_key_recv(hybrid_kex_2, conn, &shared_key_2));

    client_key_exchange_message->size = io->read_cursor - start;

    // The shared key for the PRF is ecdhe_key || kem_key
    s2n_alloc(shared_key, shared_key_1.size + shared_key_2.size);
    memcpy_check(shared_key->data, shared_key_1.data, shared_key_1.size);
    memcpy_check(shared_key->data + shared_key_1.size, shared_key_2.data, shared_key_2.size);

    GUARD(s2n_free(&shared_key_1));
    GUARD(s2n_free(&shared_key_2));

    return 0;
}

int s2n_hybrid_client_send_params(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *io = &conn->handshake.io;

    /* Keep a copy to the start of the entire hybrid client key exchange message for the hybrid PRF */
    struct s2n_blob *client_key_exchange_message = &conn->secure.client_key_exchange_message;
    client_key_exchange_message->data = s2n_stuffer_raw_read(io, 0);
    notnull_check(client_key_exchange_message->data);
    const int start = io->write_cursor;

    // key_exchange_alg->hybrid is an array of 2 pointers to s2n_kex's
    // TODO make a method for each iteration of kex
    // stuffer, call 1 add to stuffer, free, repeate
    const struct s2n_kex *hybrid_kex_1 = *conn->secure.cipher_suite->key_exchange_alg->hybrid;
    const struct s2n_kex *hybrid_kex_2 = hybrid_kex_1 + 1;

    struct s2n_blob shared_key_1 = {0};
    GUARD(s2n_kex_client_key_send(hybrid_kex_1, conn, &shared_key_1));

    struct s2n_blob shared_key_2 = {0};
    GUARD(s2n_kex_client_key_send(hybrid_kex_2, conn, &shared_key_2));

    client_key_exchange_message->size = io->write_cursor - start;

    // The shared key for the PRF is ecdhe_key || kem_key
    s2n_alloc(shared_key, shared_key_1.size + shared_key_2.size);
    memcpy_check(shared_key->data, shared_key_1.data, shared_key_1.size);
    memcpy_check(shared_key->data + shared_key_2.size, shared_key_2.data, shared_key_2.size);

    GUARD(s2n_free(&shared_key_1));
    GUARD(s2n_free(&shared_key_2));

    return 0;
}
