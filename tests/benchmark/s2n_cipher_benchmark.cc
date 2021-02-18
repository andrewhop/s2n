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

#include "s2n_benchmark.h"

extern "C" {
#include "crypto/s2n_cipher.h"
#include "tls/s2n_auth_selection.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_tls.h"
#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"
}

/* Based on supported ciphers and s2n_crypto_constants.h */
#define MAX_KEY_SIZE 64
#define MAX_MAC_KEY_SIZE 64
#define MAX_TAG 64
#define MAX_AAD 32
#define MAX_IV 32

#define MAX_MESSAGE_SIZE S2N_DEFAULT_RECORD_LENGTH

struct cipher_name {
    s2n_cipher *cipher;
    const char *name;
};


static const struct cipher_name ciphers[] = {
    {&s2n_rc4, "s2n_rc4"},
    {&s2n_aes128, "s2n_aes128"},
    {&s2n_aes256, "s2n_aes256"},
    {&s2n_3des, "s2n_3des"},
    {&s2n_aes128_gcm, "s2n_aes128_gcm"},
    {&s2n_aes256_gcm, "s2n_aes256_gcm"},
    {&s2n_aes128_sha, "s2n_aes128_sha"},
    {&s2n_aes256_sha, "s2n_aes256_sha"},
    {&s2n_aes128_sha256, "s2n_aes128_sha256"},
    {&s2n_aes256_sha256, "s2n_aes256_sha256"},
    {&s2n_chacha20_poly1305, "s2n_chacha20_poly1305"},
    {&s2n_tls13_aes128_gcm, "s2n_tls13_aes128_gcm"},
    {&s2n_tls13_aes256_gcm, "s2n_tls13_aes256_gcm"},
};
static const int message_sizes[] = {
    62, 64, 256, S2N_SMALL_RECORD_LENGTH, S2N_DEFAULT_RECORD_LENGTH
};

int run_cipher(s2n_cipher *cipher, int message_size) {
    if (cipher->type == s2n_cipher::S2N_CBC){
        message_size -= message_size % cipher->io.cbc.block_size;
    } else if (cipher->type == s2n_cipher::S2N_COMPOSITE){
        message_size -= message_size % cipher->io.comp.block_size;
    }

    s2n_stack_blob(key, cipher->key_material_size, MAX_KEY_SIZE);
    s2n_stack_blob(plaintext_message, message_size, MAX_MESSAGE_SIZE);
    s2n_stack_blob(ciphertext, message_size + MAX_TAG, MAX_MESSAGE_SIZE + MAX_TAG);

    struct s2n_session_key encryption_session_key = {};
    GUARD(s2n_session_key_alloc(&encryption_session_key));
    uint8_t iv_storage[MAX_IV] = {0};
    s2n_blob iv = {0};
    s2n_stack_blob(aad, S2N_TLS_MAX_AAD_LEN, S2N_TLS_MAX_AAD_LEN);

    GUARD(cipher->init(&encryption_session_key));
    GUARD(cipher->set_encryption_key(&encryption_session_key, &key));
    if (cipher->type == s2n_cipher::S2N_COMPOSITE) {
        uint8_t mac_size = cipher->io.comp.mac_key_size;
        s2n_stack_blob(mac_key, mac_size, MAX_MAC_KEY_SIZE);
        cipher->io.comp.set_mac_write_key(&encryption_session_key, mac_key.data, mac_key.size);
    }
    switch (cipher->type) {
        case s2n_cipher::S2N_STREAM:
            GUARD(cipher->io.stream.encrypt(&encryption_session_key, &plaintext_message, &ciphertext));
            break;
        case s2n_cipher::S2N_CBC:
            GUARD(s2n_blob_init(&iv, iv_storage, cipher->io.cbc.record_iv_size));
            GUARD(s2n_blob_init(&ciphertext, ciphertext_buf, plaintext_message.size));
            GUARD(cipher->io.cbc.encrypt(&encryption_session_key, &iv, &plaintext_message, &ciphertext));
            break;
        case s2n_cipher::S2N_AEAD:
            GUARD(s2n_blob_init(&iv, iv_storage, cipher->io.aead.record_iv_size + cipher->io.aead.fixed_iv_size));
            GUARD(cipher->io.aead.encrypt(&encryption_session_key, &iv, &aad, &plaintext_message, &ciphertext));
            break;
        case s2n_cipher::S2N_COMPOSITE:
            GUARD(s2n_blob_init(&iv, iv_storage, cipher->io.comp.record_iv_size));
            GUARD(s2n_blob_init(&ciphertext, ciphertext_buf, plaintext_message.size));
            GUARD(cipher->io.comp.encrypt(&encryption_session_key, &iv, &plaintext_message, &ciphertext));
            break;
        default:
            S2N_ERROR(S2N_ERR_CIPHER_TYPE);
    }

    return 0;
}

auto BM_test = [](benchmark::State& state, s2n_cipher *cipher, int message_size) {
    if(!cipher->is_available()) {
        state.SkipWithError("Cipher not avaliable");
    }
  for (auto _ : state) {
      BENCHMARK_SUCCESS(run_cipher(cipher, message_size));
  }
};

int main(int argc, char** argv) {
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
            std::string cipher_name = cipher.name;
            std::string benchmark_name = cipher_name + "_" + string_message;
            benchmark::RegisterBenchmark(benchmark_name.c_str(), BM_test, cipher.cipher, message_size);
        }
    }
    ::benchmark::Initialize(&argc, argv);

    GUARD(s2n_init());

    if (::benchmark::ReportUnrecognizedArguments(argc, argv)){
        return 1;
    }
    ::benchmark::RunSpecifiedBenchmarks();

    GUARD(s2n_cleanup());
}