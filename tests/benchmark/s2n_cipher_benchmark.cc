/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <benchmark/benchmark.h>
#include <s2n.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>

#include "s2n_benchmark.h"

extern "C" {
#include "crypto/s2n_cipher.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_auth_selection.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
}

/* Based on supported ciphers and s2n_crypto_constants.h */
#define MAX_KEY_SIZE 64
#define MAX_MAC_KEY_SIZE 64
#define MAX_TAG 64
#define MAX_AAD 32
#define MAX_IV 32

#define MAX_MESSAGE_SIZE 65536

struct cipher_name {
    s2n_cipher *cipher;
    const char *name;
};

static const struct cipher_name ciphers[] = {
    { &s2n_rc4, "s2n_rc4" },
    { &s2n_aes128, "s2n_aes128" },
    { &s2n_aes256, "s2n_aes256" },
    { &s2n_3des, "s2n_3des" },
    { &s2n_aes128_gcm, "s2n_aes128_gcm" },
    { &s2n_aes256_gcm, "s2n_aes256_gcm" },
    { &s2n_chacha20_poly1305, "s2n_chacha20_poly1305" },
    { &s2n_tls13_aes128_gcm, "s2n_tls13_aes128_gcm" },
    { &s2n_tls13_aes256_gcm, "s2n_tls13_aes256_gcm" },
    { &s2n_aes128_sha, "s2n_aes128_sha" },
    { &s2n_aes256_sha, "s2n_aes256_sha" },
    { &s2n_aes128_sha256, "s2n_aes128_sha256" },
    { &s2n_aes256_sha256, "s2n_aes256_sha256" },
};
static const uint32_t message_sizes[] = {
        64, 256, 1024, 4096, 10000, 16384, 65536, 262144, 1048576, 4194304, 1073741824
//    10000
    //    262144, 1048576
};

// Need to free message and original message and pass them in to save on allocation
int run_cipher(s2n_cipher *cipher, uint32_t message_size, s2n_blob *message, s2n_blob *original_message)
{
    s2n_stack_blob(key, cipher->key_material_size, MAX_KEY_SIZE);

    struct s2n_session_key encryption_session_key = {};
    struct s2n_session_key decryption_session_key = {};
    GUARD(s2n_session_key_alloc(&encryption_session_key));
    GUARD(s2n_session_key_alloc(&decryption_session_key));
    uint8_t  iv_storage[ MAX_IV ] = { 0 };
    s2n_blob iv                   = { 0 };
    s2n_stack_blob(aad, S2N_TLS_MAX_AAD_LEN, S2N_TLS_MAX_AAD_LEN);

    GUARD(cipher->init(&encryption_session_key));
    GUARD(cipher->set_encryption_key(&encryption_session_key, &key));
    GUARD(cipher->init(&decryption_session_key));
    GUARD(cipher->set_decryption_key(&decryption_session_key, &key));
    if (cipher->type == s2n_cipher::S2N_COMPOSITE) {
        uint8_t mac_size = cipher->io.comp.mac_key_size;
        s2n_stack_blob(mac_key, mac_size, MAX_MAC_KEY_SIZE);
        cipher->io.comp.set_mac_write_key(&encryption_session_key, mac_key.data, mac_key.size);
        cipher->io.comp.set_mac_write_key(&decryption_session_key, mac_key.data, mac_key.size);
    }

    switch (cipher->type) {
        case s2n_cipher::S2N_CBC:
            GUARD(s2n_blob_init(&iv, iv_storage, cipher->io.cbc.record_iv_size));
            break;
        case s2n_cipher::S2N_AEAD:
            GUARD(s2n_blob_init(&iv, iv_storage, cipher->io.aead.record_iv_size + cipher->io.aead.fixed_iv_size));

            break;
        case s2n_cipher::S2N_COMPOSITE:
            GUARD(s2n_blob_init(&iv, iv_storage, cipher->io.comp.record_iv_size));
            break;
        default:
            break;
    }

    uint32_t slice_start = 0;
    uint32_t slice_end   = MIN(message_size, S2N_TLS_MAXIMUM_FRAGMENT_LENGTH);
    while (slice_end <= message_size && slice_start != slice_end) {
        s2n_blob buff_slice = { 0 };

        GUARD(s2n_blob_slice(message, &buff_slice, slice_start, slice_end - slice_start));
        switch (cipher->type) {
            case s2n_cipher::S2N_STREAM:
                GUARD(cipher->io.stream.encrypt(&encryption_session_key, &buff_slice, &buff_slice));
                break;
            case s2n_cipher::S2N_CBC:
                GUARD(cipher->io.cbc.encrypt(&encryption_session_key, &iv, &buff_slice, &buff_slice));

                break;
            case s2n_cipher::S2N_AEAD:
                GUARD(cipher->io.aead.encrypt(&encryption_session_key, &iv, &aad, &buff_slice, &buff_slice));

                break;
            case s2n_cipher::S2N_COMPOSITE:
                GUARD(cipher->io.comp.encrypt(&encryption_session_key, &iv, &buff_slice, &buff_slice));
                break;
            default:
                S2N_ERROR(S2N_ERR_CIPHER_TYPE);
        }
        slice_start = slice_end;
        slice_end   = MIN(message_size, slice_end + S2N_TLS_MAXIMUM_FRAGMENT_LENGTH);
    }

    /* Restart for decryption */
    slice_start = 0;
    slice_end   = MIN(message_size, S2N_TLS_MAXIMUM_FRAGMENT_LENGTH);
    while (slice_end <= message_size && slice_start != slice_end) {
        s2n_blob buff_slice = { 0 };
        GUARD(s2n_blob_slice(message, &buff_slice, slice_start, slice_end - slice_start));
        switch (cipher->type) {
            case s2n_cipher::S2N_STREAM:
                GUARD(cipher->io.stream.decrypt(&decryption_session_key, &buff_slice, &buff_slice));
                break;
            case s2n_cipher::S2N_CBC:
                GUARD(cipher->io.cbc.decrypt(&decryption_session_key, &iv, &buff_slice, &buff_slice));

                break;
            case s2n_cipher::S2N_AEAD:
                GUARD(cipher->io.aead.decrypt(&decryption_session_key, &iv, &aad, &buff_slice, &buff_slice));
                /* With in place decryption this leaves the tag "in the middle" of the plaintext message
                 * just delete it here, see s2n_record_read_aead.c for how s2n normally handles this.
                 */
                memset_check(buff_slice.data + buff_slice.size - cipher->io.aead.tag_size, 0, cipher->io.aead.tag_size);

                break;
            case s2n_cipher::S2N_COMPOSITE:
                GUARD(cipher->io.comp.decrypt(&decryption_session_key, &iv, &buff_slice, &buff_slice));
                break;
            default:
                S2N_ERROR(S2N_ERR_CIPHER_TYPE);
        }
        slice_start = slice_end;
        slice_end   = MIN(message_size, slice_end + S2N_TLS_MAXIMUM_FRAGMENT_LENGTH);
    }

    GUARD(s2n_session_key_free(&encryption_session_key));
    GUARD(s2n_session_key_free(&decryption_session_key));
    eq_check(memcmp(message->data, original_message->data, message->size), 0);

    return 0;
}

auto BM_test = [](benchmark::State &state, s2n_cipher *cipher, int message_size) {
    if (!cipher->is_available()) { state.SkipWithError("Cipher not available"); }

    /* Update the message size if it's not a nice even block size for certain modes, s2n would take care of this
     * automatically
     */
    uint32_t real_message_size = message_size;
    if (cipher->type == s2n_cipher::S2N_CBC) {
        real_message_size -= real_message_size % cipher->io.cbc.block_size;
    } else if (cipher->type == s2n_cipher::S2N_COMPOSITE) {
        real_message_size -= real_message_size % cipher->io.comp.block_size;
    }

    /* Allocate the message one time to save time allocating/freeing the large tests */
    s2n_blob message          = { 0 };
    s2n_blob original_message = { 0 };
    BENCHMARK_SUCCESS(s2n_alloc(&message, real_message_size));
    BENCHMARK_SUCCESS(s2n_alloc(&original_message, real_message_size));
    /* After the allocation there could be anything in the message, we don't care what it is as long as they're the
    * same at the end */
    BENCHMARK_SUCCESS(s2n_blob_zero(&message));
    BENCHMARK_SUCCESS(s2n_blob_zero(&original_message));

    for (auto _ : state) { BENCHMARK_SUCCESS(run_cipher(cipher, message_size, &message, &original_message)); }

    BENCHMARK_SUCCESS(s2n_free(&message));
    BENCHMARK_SUCCESS(s2n_free(&original_message));

    state.SetBytesProcessed(message_size * state.iterations());
    state.SetItemsProcessed(state.iterations());
};

int main(int argc, char **argv)
{
#if defined(OPENSSL_IS_BORINGSSL)
    printf("Built with BoringSSL at 0x%x\n", OPENSSL_VERSION_NUMBER);
#elif defined(OPENSSL_IS_AWSLC)
    printf("Built with AWS-LC at 0x%x\n", OPENSSL_VERSION_NUMBER);
#else
    printf("Built with OpenSSL at 0x%lx\n", OPENSSL_VERSION_NUMBER);
#endif

    for (cipher_name cipher : ciphers) {
        for (int message_size : message_sizes) {
            std::string string_message = std::to_string(message_size);
            std::string cipher_name    = cipher.name;
            std::string benchmark_name = cipher_name + "_" + string_message;
            benchmark::RegisterBenchmark(benchmark_name.c_str(), BM_test, cipher.cipher, message_size);
        }
    }
    ::benchmark::Initialize(&argc, argv);

    GUARD(s2n_init());

    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) { return 1; }
    ::benchmark::RunSpecifiedBenchmarks();

    GUARD(s2n_cleanup());
}