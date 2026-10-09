# Development container: the same Go toolchain as CI (golang:1.27.2), so
# local and CI runs agree. No post-create fetches: the engine is
# standard-library-only in M-1, so the image is all that is needed.
#
# Development only — the deployed sensor is a static binary with no
# container dependency (C1).
# Pinned by digest (multi-arch index of golang:1.27.2); bump both together.
FROM golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c

WORKDIR /src
