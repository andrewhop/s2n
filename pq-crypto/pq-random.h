/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#ifndef S2N_PQ_RANDOM_H
#define S2N_PQ_RANDOM_H

#include "../utils/s2n_blob.h"
#include "pq-utils.h"

#ifdef NIST_RNG_FOR_UNIT_TEST
extern int randombytes(unsigned char *x, unsigned long long xlen);
#else
extern int s2n_get_private_random_data(OUT struct s2n_blob *blob);
#endif

static inline int get_random_bytes(OUT unsigned char *buffer, unsigned int num_bytes)
{
#ifdef NIST_RNG_FOR_UNIT_TEST
    return randombytes(buffer, (unsigned long long)num_bytes);
#else
    struct s2n_blob out = {.data = buffer,.size = num_bytes };
    return s2n_get_private_random_data(&out);
#endif
}
#endif //S2N_PQ_RANDOM_H
