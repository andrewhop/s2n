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

#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

#include "pq-crypto/bike/bike1_l1_kem.h"
#include "pq-crypto/sike/sike_p503_kem.h"

#include "tls/s2n_kem.h"

const struct s2n_kem bike1_level1 = {
        .named_kem = BIKE1_Level1,
        .publicKeySize = BIKE1_L1_PUBLIC_KEY_BYTES,
        .privateKeySize = BIKE1_L1_SECRET_KEY_BYTES,
        .sharedSecretKeySize = BIKE1_L1_SECRET_KEY_BYTES,
        .ciphertextSize = BIKE1_L1_CIPHERTEXT_BYTES,
        .generate_keypair = &BIKE1_L1_crypto_kem_keypair,
        .encrypt = &BIKE1_L1_crypto_kem_enc,
        .decrypt = &BIKE1_L1_crypto_kem_dec,
};

const struct s2n_kem sikep503 = {
        .named_kem = SIKEp503_KEM,
        .publicKeySize = SIKE_P503_PUBLIC_KEY_BYTES,
        .privateKeySize = SIKE_P503_SECRET_KEY_BYTES,
        .sharedSecretKeySize = SIKE_P503_SHARED_SECRET_BYTES,
        .ciphertextSize = SIKE_P503_CIPHERTEXT_BYTES,
        .generate_keypair = &SIKE_P503_crypto_kem_keypair,
        .encrypt = &SIKE_P503_crypto_kem_enc,
        .decrypt = &SIKE_P503_crypto_kem_dec,
};

int s2n_kem_generate_key_pair(const struct s2n_kem *kem, struct s2n_kem_params *params)
{
    notnull_check(kem->generate_keypair);
    GUARD(s2n_alloc(&params->public_key, kem->publicKeySize));
    GUARD(s2n_alloc(&params->private_key, kem->privateKeySize));
    GUARD(kem->generate_keypair(params->public_key.data, params->private_key.data));
    return 0;
}

int s2n_kem_generate_shared_secret(const struct s2n_kem *kem, struct s2n_kem_params *params,
                                   struct s2n_blob *shared_secret, struct s2n_blob *ciphertext)
{
    notnull_check(kem->encrypt);
    GUARD(s2n_alloc(shared_secret, kem->sharedSecretKeySize));
    GUARD(s2n_alloc(ciphertext, kem->ciphertextSize));
    GUARD(kem->encrypt(ciphertext->data, shared_secret->data, params->public_key.data));
    return 0;
}

int s2n_kem_decrypt_shared_secret(const struct s2n_kem *kem, struct s2n_kem_params *params,
                                  struct s2n_blob *shared_secret, struct s2n_blob *ciphertext)
{
    notnull_check(kem->decrypt);
    notnull_check(params->private_key.data);
    eq_check(kem->ciphertextSize, ciphertext->size);

    GUARD(s2n_alloc(shared_secret, kem->sharedSecretKeySize));
    GUARD(kem->decrypt(shared_secret->data, ciphertext->data, params->private_key.data));
    return 0;
}
