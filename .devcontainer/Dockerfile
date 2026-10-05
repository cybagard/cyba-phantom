# Development container: the same Go toolchain as CI (golang:1.27.1), so
# local and CI runs agree. No post-create fetches: the engine is
# standard-library-only in M-1, so the image is all that is needed.
#
# Development only — the deployed sensor is a static binary with no
# container dependency (C1).
# Pinned by digest (multi-arch index of golang:1.27.1); bump both together.
FROM golang:1.27.1@sha256:e0174e51e81218523251d85d248a90d24c3d5e81543b4f07a5d66229397db190

WORKDIR /src
