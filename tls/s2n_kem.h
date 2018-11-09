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

#pragma once

#include <stdint.h>
#include "tls/s2n_kem_params.h"

enum NamedBIKEKEM {
    BIKE1_Level1 = 1,
    BIKE1_Leve3 = 2,
    BIKE1_Level5 = 3,
    BIKE2_Level1 = 4,
    BIKE2_Leve3 = 5,
    BIKE2_Level5 = 6,
    BIKE3_Level1 = 7,
    BIKE3_Leve3 = 8,
    BIKE3_Level5 = 9
};

extern const enum NamedBIKEKEM s2n_supported_bike_kem[1];

enum NamedSIKEKEM {
    SIKEp503_KEM = 1,
    SIKEp751_KEM = 2,
    SIKEp964_KEM = 3,

};

extern const enum NamedSIKEKEM s2n_supported_sike_kem[1];

struct s2n_kem {
    uint8_t named_kem;
    const uint16_t publicKeySize;
    const uint16_t privateKeySize;
    const uint16_t sharedSecretKeySize;
    const uint16_t ciphertextSize;
    int (*generate_keypair)(unsigned char *public_key, unsigned char *private_key);
    int (*encrypt)(unsigned char *ciphertext, unsigned char *shared_secret,  const unsigned char *public_key);
    int (*decrypt)(unsigned char *shared_secret, const unsigned char *ciphertext, const unsigned char *private_key);
};

extern const struct s2n_kem bike1_level1;
extern const struct s2n_kem sikep503;

extern int s2n_kem_generate_key_pair(const struct s2n_kem *kem, struct s2n_kem_params *params);

extern int s2n_kem_generate_shared_secret(const struct s2n_kem *kem, struct s2n_kem_params *params,
                                          struct s2n_blob *shared_secret, struct s2n_blob *ciphertext);

extern int s2n_kem_decrypt_shared_secret(const struct s2n_kem *kem, struct s2n_kem_params *params,
                                         struct s2n_blob *shared_secret, struct s2n_blob *ciphertext);
