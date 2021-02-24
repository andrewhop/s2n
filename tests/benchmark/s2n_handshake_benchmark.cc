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
#include "tls/s2n_auth_selection.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_tls.h"
#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"
}

struct test_case {
    const struct s2n_ecc_named_curve *curve_to_test;
    const struct s2n_kem *kem_to_test;
    struct s2n_cipher_suite *cipher_suite_to_test;
};

static const struct test_case tests[] = {
    {nullptr, nullptr, &s2n_dhe_rsa_with_aes_256_gcm_sha384},
    {&s2n_ecc_curve_secp256r1, nullptr, &s2n_ecdhe_rsa_with_aes_256_gcm_sha384},
    {&s2n_ecc_curve_secp384r1, nullptr, &s2n_ecdhe_rsa_with_aes_256_gcm_sha384},
    {&s2n_ecc_curve_secp521r1, nullptr, &s2n_ecdhe_rsa_with_aes_256_gcm_sha384},
#if EVP_APIS_SUPPORTED
    {&s2n_ecc_curve_x25519, nullptr, &s2n_ecdhe_rsa_with_aes_256_gcm_sha384},
#endif
    {&s2n_ecc_curve_secp256r1, &s2n_sike_p503_r1, &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384},
    {&s2n_ecc_curve_secp256r1, &s2n_sike_p434_r2, &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384},
    {&s2n_ecc_curve_secp256r1, &s2n_bike1_l1_r1, &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384},
    {&s2n_ecc_curve_secp256r1, &s2n_bike1_l1_r2, &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384},
    {&s2n_ecc_curve_secp256r1, &s2n_kyber_512_r2, &s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384},
};

static char *server_dhparams_pem = nullptr;
static char *server_cert_chain = nullptr;
static char *server_private_key = nullptr;
static char *client_chain = nullptr;
static struct s2n_cert_chain_and_key *server_chain_and_key = nullptr;
static struct s2n_config *server_config = nullptr;
struct s2n_connection *client_conn;
struct s2n_connection *server_conn;
struct s2n_blob client_asn1der = {0};

static int one_time_setup() {
    /* Server setup */
    GUARD_NONNULL(server_conn = s2n_connection_new(S2N_SERVER));
    GUARD_NONNULL(server_config = s2n_config_new());
    GUARD(s2n_connection_set_config(server_conn, server_config));

    GUARD_NONNULL(server_cert_chain = (char*) malloc(S2N_MAX_TEST_PEM_SIZE));
    GUARD_NONNULL(server_private_key = (char*) malloc(S2N_MAX_TEST_PEM_SIZE));
    GUARD_NONNULL(client_chain = (char*) malloc(S2N_MAX_TEST_PEM_SIZE));
    GUARD(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, server_cert_chain, S2N_MAX_TEST_PEM_SIZE));
    GUARD(s2n_read_test_pem(S2N_RSA_2048_PKCS1_KEY, server_private_key, S2N_MAX_TEST_PEM_SIZE));
    GUARD(s2n_read_test_pem(S2N_RSA_2048_PKCS1_LEAF_CERT, client_chain, S2N_MAX_TEST_PEM_SIZE));
    GUARD_NONNULL(server_chain_and_key = s2n_cert_chain_and_key_new());
    GUARD(s2n_cert_chain_and_key_load_pem(server_chain_and_key, server_cert_chain, server_private_key));
    GUARD(s2n_config_add_cert_chain_and_key_to_store(server_config, server_chain_and_key));

    GUARD_NONNULL(server_dhparams_pem = (char*) malloc(S2N_MAX_TEST_PEM_SIZE));
    GUARD(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, server_dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
    GUARD(s2n_config_add_dhparams(server_config, server_dhparams_pem));

    /* Client setup */
    GUARD_NONNULL(client_conn = s2n_connection_new(S2N_CLIENT));

    DEFER_CLEANUP(struct s2n_stuffer certificate_in = {0}, s2n_stuffer_free);
    GUARD(s2n_stuffer_alloc(&certificate_in, S2N_MAX_TEST_PEM_SIZE));
    DEFER_CLEANUP(struct s2n_stuffer certificate_out = {0}, s2n_stuffer_free);
    GUARD(s2n_stuffer_alloc(&certificate_out, S2N_MAX_TEST_PEM_SIZE));

    GUARD(s2n_blob_init(&client_asn1der, (uint8_t *) client_chain, strlen(client_chain) + 1));
    GUARD(s2n_stuffer_write(&certificate_in, &client_asn1der));
    GUARD(s2n_stuffer_certificate_from_pem(&certificate_in, &certificate_out));

    client_asn1der.size = s2n_stuffer_data_available(&certificate_out);
    GUARD(s2n_stuffer_read(&certificate_out, &client_asn1der));

    return 0;
}

int one_time_cleanup() {
    free(server_dhparams_pem);
    free(server_cert_chain);
    free(client_chain);
    free(server_private_key);
    GUARD(s2n_cert_chain_and_key_free(server_chain_and_key));
    GUARD(s2n_config_free(server_config));
    GUARD(s2n_connection_free(server_conn));
    GUARD(s2n_connection_free(client_conn));

    return 0;
}


static int configure_server_for_test(struct test_case test) {
    server_conn->secure.kem_params.kem = test.kem_to_test;
    server_conn->secure.cipher_suite = test.cipher_suite_to_test;
    server_conn->secure.server_ecc_evp_params.negotiated_curve = test.curve_to_test;
    GUARD(s2n_choose_sig_scheme_from_peer_preference_list(server_conn, &server_conn->handshake_params.client_sig_hash_algs,
                                                          &server_conn->secure.conn_sig_scheme));
    server_conn->handshake_params.our_chain_and_key = server_chain_and_key;
    server_conn->actual_protocol_version = S2N_TLS12;
    GUARD(s2n_choose_default_sig_scheme(server_conn, &server_conn->secure.conn_sig_scheme));
    return 0;
}

static int configure_client_for_test(struct test_case test) {
    client_conn->secure.kem_params.kem = test.kem_to_test;
    client_conn->secure.cipher_suite = test.cipher_suite_to_test;
    client_conn->secure.server_ecc_evp_params.negotiated_curve = test.curve_to_test;
    client_conn->config->security_policy = &security_policy_pq_tls_1_0_2020_12;
    client_conn->actual_protocol_version = S2N_TLS12;

    s2n_pkey_type temp_pkey_type = {};
    /* This loads the public key that will be used for verification during the handshake */
    GUARD(s2n_asn1der_to_public_key_and_type(&client_conn->secure.server_public_key, &temp_pkey_type, &client_asn1der));
    return 0;
}

static int run_handshake(struct test_case test) {
    GUARD(configure_server_for_test(test));
    GUARD(configure_client_for_test(test));

    /* Part 1: Server calls send_key */
    GUARD(s2n_server_key_send(server_conn));
    uint32_t server_length = server_conn->handshake.io.write_cursor - server_conn->handshake.io.read_cursor;
    struct s2n_blob server_key_message = {
        static_cast<uint8_t *>(s2n_stuffer_raw_read(&server_conn->handshake.io, server_length)), server_length};
    GUARD_NONNULL(server_key_message.data);

    /* Part 1.1: feed that to the client */
    GUARD(s2n_stuffer_write(&client_conn->handshake.io, &server_key_message));

    /* Part 2: Client calls recv_read and recv_parse */
    GUARD(s2n_server_key_recv(client_conn));


    /* Part 3: Client calls send_key. */
    GUARD(s2n_client_key_send(client_conn));
    uint32_t client_length = client_conn->handshake.io.write_cursor - client_conn->handshake.io.read_cursor;
    struct s2n_blob client_key_message = {
        static_cast<uint8_t *>(s2n_stuffer_raw_read(&client_conn->handshake.io, client_length)), client_length};
    GUARD_NONNULL(client_key_message.data);

    /* Part 3.1: Send that back to the server */
    GUARD(s2n_stuffer_write(&server_conn->handshake.io, &client_key_message));

    /* Part 4: Call client key recv */
    GUARD(s2n_client_key_recv(server_conn));
    eq_check(memcmp(client_conn->secure.master_secret, server_conn->secure.master_secret, S2N_TLS_SECRET_LEN), 0);

    GUARD(s2n_connection_wipe(client_conn));
    GUARD(s2n_connection_wipe(server_conn));

    return 0;
}

auto BM_test = [](benchmark::State& state, struct test_case test) {
  for (auto _ : state) {
      BENCHMARK_SUCCESS(run_handshake(test));
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

    for (struct test_case test : tests) {
        std::string cipher_name = test.cipher_suite_to_test == nullptr ? "null" : test.cipher_suite_to_test->name;
        std::string curve_name = test.curve_to_test == nullptr ? "null" : test.curve_to_test->name;
        std::string kem_name = test.kem_to_test == nullptr ? "null" : test.kem_to_test->name;
        std::string benchmark_name = curve_name + "__" + kem_name + "__" + cipher_name;
        benchmark::RegisterBenchmark(benchmark_name.c_str(), BM_test, test);
    }
    ::benchmark::Initialize(&argc, argv);

    GUARD(s2n_init());
    GUARD(one_time_setup());

    if (::benchmark::ReportUnrecognizedArguments(argc, argv)){
        return 1;
    }
    ::benchmark::RunSpecifiedBenchmarks();

    GUARD(one_time_cleanup());

    GUARD(s2n_cleanup());
}