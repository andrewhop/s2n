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
FROM ubuntu:disco-20191030

SHELL ["/bin/bash", "-c"]

# ENV variables are available when the image (and thus the CodeBuild build) are running and during image build time
ENV OPENSSL_1_1_1_INSTALL_DIR=/test-deps/openssl-1.1.1 \
    PYTHON_INSTALL_DIR=/test-deps/python \
    GNUTLS_INSTALL_DIR=/test-deps/gnutls


# ARG variables are only available while building the image
ARG PYTHON_TEMP=/tmp/python
ARG OPENSSL_TEMP=/tmp/openssl
ARG GNU_TEMP=/tmp/gnutls

COPY setup_scripts/install_common_ubuntu-19.04_dependencies.sh /tmp/install_common_ubuntu-19.04_dependencies.sh
COPY setup_scripts/install_openssl_1_1_1.sh /tmp/install_openssl_1_1_1.sh
COPY setup_scripts/install_python.sh /tmp/install_python.sh
COPY setup_scripts/install_gnutls.sh /tmp/install_gnutls.sh
COPY setup_scripts/install_sslyze.sh /tmp/install_sslyze.sh

RUN set -ex && \
    apt-get update

RUN set -ex && \
    mkdir -p $OPENSSL_1_1_1_INSTALL_DIR $PYTHON_INSTALL_DIR $PYTHON_TEMP $OPENSSL_TEMP
    /tmp/install_common_ubuntu-19.04_dependencies.sh && \
    /tmp/install_sslyze.sh

