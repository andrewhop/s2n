# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

# Disco is the code name for the 19.04 release. The official 19.04 tag appears to act like a latest which we don't want.
# Disco gets specific versions and disco-20191030 is the latest. https://hub.docker.com/_/ubuntu/
FROM ubuntu:disco-20191030

SHELL ["/bin/bash", "-c"]
RUN set -ex && \
    apt-get update

# gcc-8=8.3.0-1ubuntu3 aka gcc 8.3.0 is the latest version of gcc if you run `apt-cache policy gcc`
RUN set -ex && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install \
    gcc-8=8.3.0-6ubuntu1 \
    make=4.2.1-1.2 \
    libssl-dev=1.1.1b-1ubuntu2.4

RUN set -ex && \
    apt-get autoremove --purge -y && \
    apt-get clean && \
    apt-get autoclean && \
    rm -rf /tmp/*
