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

extern int s2n_get_private_random_data(OUT struct s2n_blob *blob);

static inline int get_random_bytes(OUT unsigned char *buffer, int num_bytes)
{
    struct s2n_blob out = {.data = buffer,.size = num_bytes };
    if (s2n_get_private_random_data(&out) < 0) {
        return 0;
    }
    return 1;
}
#endif //S2N_PQ_RANDOM_H
