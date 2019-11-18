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
# ENV variables are avliable when the image (and thus the CodeBuild build) are running
ENV OPENSSL_1_1_1_INSTALL_DIR=/test-deps/openssl-1.1.1 \
    PYTHON_INSTALL_DIR=/test-deps/python

# ARG varliable are only avliable while building the image
ARG PYTHON_TEMP=/tmp/python \
    OPENSSL_TEMP=/tmp/openssl

RUN set -ex && \
    apt-get update

# clang=1:8.0-48~exp1ubuntu1 aka clang 8.0.0 is the latest version of clang if you run `apt-cache policy clang`
RUN set -ex && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install \
    gcc-8=8.3.0-6ubuntu1 \
    g++-8=8.3.0-6ubuntu1
    make=4.2.1-1.2

RUN set -ex && \
    mkdir -p $OPENSSL_1_1_1_INSTALL_DIR $PYTHON_INSTALL_DIR $PYTHON_TEMP $OPENSSL_TEMP && \
    ./setup_scripts/install_openssl_1_1_1.sh $OPENSSL_TEMP $OPENSSL_1_1_1_INSTALL_DIR && \
    ./setup_scripts/install_python.sh $OPENSSL_1_1_1_INSTALL_DIR $PYTHON_TEMP $PYTHON_INSTALL_DIR

RUN set -ex && \
    apt-get remove g++-8 -y && \
    apt-get autoremove --purge -y && \
    apt-get clean && \
    apt-get autoclean && \
    rm -rf /tmp/*
