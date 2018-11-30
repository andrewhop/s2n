/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "s2n_test.h"

#include <string.h>
#include <stdio.h>

#include <s2n.h>
#include <tls/s2n_cipher_suites.h>

#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_prf.h"
#include "utils/s2n_safety.h"

int convert_hex_to_bytes(uint8_t output[], char input[])
{
    struct s2n_stuffer stuffer_in = {0};
    GUARD(s2n_stuffer_alloc_ro_from_string(&stuffer_in, input));
    for (int i = 0; i < strlen(input)/2; i++) {
        uint8_t c;
        GUARD(s2n_stuffer_read_uint8_hex(&stuffer_in, &c));
        output[i] = c;
    }
    GUARD(s2n_stuffer_free(&stuffer_in));

    return 0;
}

int main(int argc, char **argv)
{
    // ECDHE + SIKE KAT
    char premaster_secret_hex_in[] = "e45c242e720129feaafafea3dccb73b5562906657505525db4074c403215284992df25062a61091651dd5e9dd3401a724346C330BBB2526CECFCC8238FA86913";
    char client_random_hex_in[] = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20";
    char server_random_hex_in[] = "2122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40";
    char client_key_exchange_message[] = "16030301FD100001F66104aaaef1b8bf482280aeb8eaa9ef104b12f9526c58ba4d0223e2db988284251dd0755744ccb7e3addcd6757d4e2b9f9829275cd152f9c99b67df8cb5de032aa593a23b66d20b6a9c9670cb49d593b8d8fc954978545cd8d57e758625ec67dc8f80019289611D5DB90BAA5BCC1F076B0B1FA275D8EAB09FD4EBD8B5D05D0864F95815CEF9F7952612968A459FA5C5F3791534916EC4F77C44CC59ED0EF96E44D45020B381FFD4F974AF89D41017C95B04E852174307B629D8479737BF3B5A597FD7689B00D2078D0D4D45166C49ECE65FB84D00EFF1E0A70D5727306865EBC8FF25C6F718BD4EFCE230A9317A01ABB35DBD00004146B9C9EA33FF4C43F541E0AFC23A7409F769AA8B25FF0AA6A3E41A7C7ADBD02043DAE72B794F1EBF123DAE1E06782D9F1287EE5D88813BE64BFD0B67D751AA6AAA6FC3B27D3F7FD9766D9B9AA5EF3CD4061898F37D916CD9378931EBF0234F00932200F2489ABD35944328D09178104970E9BBE25FA81ACA265DACF045A81897246A347B6CCCF70CB65E375A6F629D847A48AF98DE8165C3AFA882B5143CF2F453B5A39A5329E091542EE40B5D16367808F536EC39761B37D635943D312FF1DCDAF2254FA45D549DADBF5A999CBF1D9985908AA3D740DC59138EE19ABA882B3D4758B72C0DB81D681AAE44096514DBFF5E9512687025808CA10F45D395DF515FB0";
    char expected_master_secret_hex_in[] = "70875ee292ce7867f3c07399566cbc7933ae39dcb395f4c72c27f26cc0535858a2524ca5842aa1ce2fa5bb53b5d9415b";

    struct s2n_blob pms = {0};
    s2n_alloc(&pms, strlen(premaster_secret_hex_in));
    uint8_t expected_master_secret[96];

    struct s2n_connection *conn;

    BEGIN_TEST();

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

    conn->actual_protocol_version = S2N_TLS12;
    // Really only need for the hash function in the PRF
    conn->secure.cipher_suite = &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384;
    s2n_alloc(&conn->secure.client_key_exchange_message, strlen(client_key_exchange_message)/2);

    convert_hex_to_bytes(conn->secure.client_random, client_random_hex_in);
    convert_hex_to_bytes(conn->secure.server_random, server_random_hex_in);
    convert_hex_to_bytes(conn->secure.client_key_exchange_message.data, client_key_exchange_message);
    convert_hex_to_bytes(pms.data, premaster_secret_hex_in);
    convert_hex_to_bytes(expected_master_secret, expected_master_secret_hex_in);

    s2n_hybrid_prf_master_secret(conn, &pms);

    EXPECT_BYTEARRAY_EQUAL(expected_master_secret, conn->secure.master_secret, strlen(expected_master_secret_hex_in)/2);
    END_TEST();
}
