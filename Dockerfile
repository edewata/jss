#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

ARG BASE_IMAGE="registry.fedoraproject.org/fedora:latest"
ARG COPR_REPO=""
ARG JAVA_VERSION="17"

################################################################################
FROM $BASE_IMAGE AS jss-base

RUN dnf install -y dnf-plugins-core systemd \
    && dnf clean all \
    && rm -rf /var/cache/dnf

CMD [ "/usr/sbin/init" ]

################################################################################
FROM jss-base AS jss-deps

ARG COPR_REPO

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf copr enable -y $COPR_REPO; fi

# Install JSS runtime dependencies
RUN dnf install -y dogtag-jss \
    && rpm -e --nodeps $(rpm -qa java-* dogtag-*) \
    && dnf clean all \
    && rm -rf /var/cache/dnf

################################################################################
FROM jss-deps AS jss-builder-deps

ARG JAVA_VERSION

# Import JSS sources
COPY jss.spec /root/jss/
COPY build.sh /root/jss/
WORKDIR /root/jss

# Install JSS build dependencies
RUN dnf install -y rpm-build \
    && ./build.sh \
        --work-dir=build \
        --java-version=$JAVA_VERSION \
        spec \
    && dnf builddep \
        -y \
        --spec build/SPECS/jss.spec \
    && dnf clean all \
    && rm -rf /var/cache/dnf

################################################################################
FROM jss-builder-deps AS jss-builder

# Import JSS source
COPY . /root/jss/

# Build JSS packages
RUN ./build.sh \
    --work-dir=build \
    --java-version=$JAVA_VERSION \
    rpm

################################################################################
FROM alpine:latest AS jss-dist

# Import JSS packages
COPY --from=jss-builder /root/jss/build/SRPMS /root/SRPMS/
COPY --from=jss-builder /root/jss/build/RPMS /root/RPMS/

################################################################################
FROM jss-deps AS jss-runner

# Import JSS packages
COPY --from=jss-dist /root/RPMS /tmp/RPMS/

# Install JSS packages
RUN dnf localinstall -y /tmp/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf /tmp/RPMS

