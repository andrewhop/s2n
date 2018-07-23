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

#include "s2n_test.h"

#include "pq-crypto/bike/bike1_l1_kem.h"
#include "pq-crypto/bike/utilities.h"

uint32_t constant_time_compare(IN const uint8_t* a,
                  IN const uint8_t* b,
                  IN const uint32_t size)
{
    volatile uint8_t res = 0;

    for(uint32_t i=0; i < size; ++i)
    {
        res |= (a[i] ^ b[i]);
    }

    return (res == 0);
}

int main(int argc, char **argv)
{
    unsigned char publicKey[N_SIZE];
    unsigned char privateKey[N_SIZE];
    unsigned char plaintextSecret[ELL_K_SIZE];
    unsigned char sharedSecret[ELL_K_SIZE];
    unsigned char encryptedSecret[ELL_K_SIZE];


    BEGIN_TEST();

    EXPECT_SUCCESS(BIKE1_L1_crypto_kem_keypair(publicKey, privateKey));
    EXPECT_SUCCESS(BIKE1_L1_crypto_kem_enc(encryptedSecret, plaintextSecret, publicKey));
    EXPECT_SUCCESS(BIKE1_L1_crypto_kem_dec(sharedSecret, encryptedSecret, privateKey));
    EXPECT_SUCCESS(constant_time_compare(plaintextSecret, sharedSecret, ELL_K_BITS));

    END_TEST();
}