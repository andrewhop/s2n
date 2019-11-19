#!/bin/bash
# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

DEBIAN_FRONTEND=noninteractive apt-get -y install \
    curl=7.64.0-2ubuntu1.2 \
    unzip=6.0-22ubuntu1 \
    perl=5.28.1-6 \
    zlibc=0.9k-4.3 \
    make=4.2.1-1.2 \
    zlib1g-dev=1:1.2.11.dfsg-1ubuntu2