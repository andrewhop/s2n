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

extern "C" {
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_kex.h"
#include "testlib/s2n_testlib.h"
}

/* These KEX's do not need a KEM configured */
static const struct s2n_kex simple_kex[] = {
    s2n_rsa,
    s2n_dhe,
    s2n_ecdhe,
};

/* These KEX's need a KEM to be configured to succed */
static const struct s2n_kex kem_kex[] = {
    s2n_kem,
    s2n_hybrid_ecdhe_kem,
};

static int run_kex(const struct s2n_kex *kex_to_test, const struct s2n_ecc_named_curve *curve_to_test,
                   const struct s2n_kem *kem_to_test, struct s2n_cipher_suite *cipher_suite_to_test) {
    struct s2n_connection *client_conn;
    struct s2n_connection *server_conn;

    GUARD_NONNULL(client_conn = s2n_connection_new(S2N_CLIENT));
    GUARD_NONNULL(server_conn = s2n_connection_new(S2N_SERVER));

    client_conn->secure.kem_params.kem = kem_to_test;
    client_conn->secure.cipher_suite->key_exchange_alg = kex_to_test;
    client_conn->secure.cipher_suite = cipher_suite_to_test;
    client_conn->secure.server_ecc_evp_params.negotiated_curve = curve_to_test;
    client_conn->config->security_policy = &security_policy_pq_tls_1_0_2020_12;
    server_conn->secure.kem_params.kem = kem_to_test;
    server_conn->secure.cipher_suite->key_exchange_alg = kex_to_test;
    server_conn->secure.server_ecc_evp_params.negotiated_curve = curve_to_test;
//    struct s2n_dh_params dh_params = {0};
//    struct s2n_stuffer dhparams_out = {0};
//    uint32_t available_size = 0;
//
//    available_size = s2n_stuffer_data_available(&dhparams_out);
//    struct s2n_blob b = {0};
//    struct s2n_config *config = NULL;
//    GUARD_NONNULL(config = s2n_config_new());
//    char *dhparams_pem = NULL;
//    GUARD_NONNULL(dhparams_pem = static_cast<char *>(malloc(S2N_MAX_TEST_PEM_SIZE)));
//    GUARD(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
//
//    GUARD(s2n_blob_init(&b, static_cast<uint8_t *>(s2n_stuffer_raw_read(&dhparams_out, available_size)), available_size));
//    GUARD(s2n_pkcs3_to_dh_params(&dh_params, &b));
//
//    GUARD(s2n_config_add_dhparams(config, dhparams_pem));

    /* Part 1: Server calls send_key */
    struct s2n_blob data_to_sign = {0};
    GUARD_AS_POSIX(s2n_kex_server_key_send(kex_to_test, server_conn, &data_to_sign));
    uint32_t server_length = server_conn->handshake.io.write_cursor - server_conn->handshake.io.read_cursor;
    struct s2n_blob server_key_message = {
        static_cast<uint8_t *>(s2n_stuffer_raw_read(&server_conn->handshake.io, server_length)), server_length};
    GUARD_NONNULL(server_key_message.data);

    /* Part 1.1: feed that to the client */
    GUARD(s2n_stuffer_write(&client_conn->handshake.io, &server_key_message));

    /* Part 2: Client calls recv_read and recv_parse */
    struct s2n_kex_raw_server_data raw_params = {0};
    struct s2n_blob data_to_verify = {0};
    GUARD_AS_POSIX(s2n_kex_server_key_recv_read_data(kex_to_test, client_conn, &data_to_verify, &raw_params));
    GUARD_AS_POSIX(s2n_kex_server_key_recv_parse_data(kex_to_test, client_conn, &raw_params));


    /* Part 3: Client calls send_key. */
    struct s2n_blob client_shared_key = {0};
    GUARD_AS_POSIX(s2n_kex_client_key_send(kex_to_test, client_conn, &client_shared_key));
    uint32_t client_length = client_conn->handshake.io.write_cursor - client_conn->handshake.io.read_cursor;
    struct s2n_blob client_key_message = {
        static_cast<uint8_t *>(s2n_stuffer_raw_read(&client_conn->handshake.io, client_length)), client_length};
    GUARD_NONNULL(client_key_message.data);

    /* Part 3.1: Send that back to the server */
    GUARD(s2n_stuffer_write(&server_conn->handshake.io, &client_key_message));

    /* Part 4: Call client key recv */
    struct s2n_blob server_shared_key = { 0 };
    GUARD_AS_POSIX(s2n_kex_client_key_recv(kex_to_test, server_conn, &server_shared_key));
    eq_check(memcmp(client_shared_key.data, server_shared_key.data, server_shared_key.size), 0);

    GUARD(s2n_connection_free(client_conn));
    GUARD(s2n_connection_free(server_conn));

    return 0;
}

static void BM_ecdhe_256_null(benchmark::State& state) {
    for (auto _ : state) {
        if(0 != run_kex(&s2n_ecdhe, &s2n_ecc_curve_secp256r1, NULL, &s2n_ecdhe_rsa_with_aes_256_gcm_sha384)) {
            state.SkipWithError("Failed to run kex");
        }
    }
}

static void BM_ecdhe_384_null(benchmark::State& state) {
    for (auto _ : state) {
        if(0 != run_kex(&s2n_ecdhe, &s2n_ecc_curve_secp384r1, NULL, &s2n_ecdhe_rsa_with_aes_256_gcm_sha384)) {
            state.SkipWithError("Failed to run kex");
        }
    }
}

static void BM_ecdhe_521_null(benchmark::State& state) {
    for (auto _ : state) {
        if(0 != run_kex(&s2n_ecdhe, &s2n_ecc_curve_secp521r1, NULL, &s2n_ecdhe_rsa_with_aes_256_gcm_sha384)) {
            state.SkipWithError("Failed to run kex");
        }
    }
}

static void BM_ecdhe_x25519_null(benchmark::State& state) {
    for (auto _ : state) {
        if(0 != run_kex(&s2n_ecdhe, &s2n_ecc_curve_x25519, NULL, &s2n_ecdhe_rsa_with_aes_256_gcm_sha384)) {
            state.SkipWithError("Failed to run kex");
        }
    }
}

static void BM_ecdhe_256_sike_p503_r1(benchmark::State& state) {
    for (auto _ : state) {
        if(0 != run_kex(&s2n_hybrid_ecdhe_kem, &s2n_ecc_curve_secp256r1, &s2n_sike_p503_r1, &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384)) {
            state.SkipWithError("Failed to run kex");
        }
    }
}

static void BM_ecdhe_256_sike_p434_r2(benchmark::State& state) {
    for (auto _ : state) {
        if(0 != run_kex(&s2n_hybrid_ecdhe_kem, &s2n_ecc_curve_secp256r1, &s2n_sike_p434_r2, &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384)) {
            state.SkipWithError("Failed to run kex");
        }
    }
}

static void BM_ecdhe_256_bike_l1_r1(benchmark::State& state) {
    for (auto _ : state) {
        if(0 != run_kex(&s2n_hybrid_ecdhe_kem, &s2n_ecc_curve_secp256r1, &s2n_bike1_l1_r1, &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384)) {
            state.SkipWithError("Failed to run kex");
        }
    }
}

static void BM_ecdhe_256_bike_l1_r2(benchmark::State& state) {
    for (auto _ : state) {
        if(0 != run_kex(&s2n_hybrid_ecdhe_kem, &s2n_ecc_curve_secp256r1, &s2n_bike1_l1_r2, &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384)) {
            state.SkipWithError("Failed to run kex");
        }
    }
}
static void BM_ecdhe_256_kyber_512_r2(benchmark::State& state) {
    for (auto _ : state) {
        if(0 != run_kex(&s2n_hybrid_ecdhe_kem, &s2n_ecc_curve_secp256r1, &s2n_kyber_512_r2, &s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384)) {
            state.SkipWithError("Failed to run kex");
        }
    }
}

BENCHMARK(BM_ecdhe_256_null);
BENCHMARK(BM_ecdhe_384_null);
BENCHMARK(BM_ecdhe_521_null);
BENCHMARK(BM_ecdhe_x25519_null);
BENCHMARK(BM_ecdhe_256_kyber_512_r2);
BENCHMARK(BM_ecdhe_256_bike_l1_r1);
BENCHMARK(BM_ecdhe_256_bike_l1_r2);
BENCHMARK(BM_ecdhe_256_sike_p503_r1);
BENCHMARK(BM_ecdhe_256_sike_p434_r2);

int main(int argc, char** argv) {
#if defined(OPENSSL_IS_BORINGSSL)
    printf("Build with BoringSSL at 0x%x\n", OPENSSL_VERSION_NUMBER);
#elif defined(OPENSSL_IS_AWSLC)
    printf("Build with AWS-LC at 0x%x\n", OPENSSL_VERSION_NUMBER);
#else
    printf("Build with OpenSSL at 0x%lx\n", OPENSSL_VERSION_NUMBER);
#endif
    ::benchmark::Initialize(&argc, argv);
    GUARD(s2n_init());


    if (::benchmark::ReportUnrecognizedArguments(argc, argv)){
        return 1;
    }
    ::benchmark::RunSpecifiedBenchmarks();

    GUARD(s2n_cleanup());
}