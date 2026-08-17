# Build/tooling image for the backend. Not part of the running stack.
#
# Two jobs:
#   1. Reproduce the CI environment locally — Temurin 21, same distribution as
#      actions/setup-java, so `mvnw verify` here means the same thing it means in CI.
#   2. Build the application image with Jib, which registers it with the Docker daemon
#      and therefore needs the `docker` CLI plus a mounted /var/run/docker.sock.
#
# Built by `make builder`; see the Makefile for the invocations.

FROM docker:27-cli AS docker-cli

# Temurin 21 with Maven preinstalled. The wrapper (./mvnw) is what CI runs and what the
# Makefile targets use; the bundled mvn only bootstraps the project.
FROM maven:3.9-eclipse-temurin-21

# Statically linked release binary — safe to lift out of the Alpine-based CLI image.
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

# Without unzip, mvnw downloads the .tar.gz distribution while
# distributionSha256Sum in maven-wrapper.properties describes the .zip, and the
# wrapper aborts on a checksum mismatch. GitHub's ubuntu runners ship unzip, so
# this keeps the local build on the same path as CI.
RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
