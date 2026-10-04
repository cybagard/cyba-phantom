# Development container: the same Go toolchain as CI (golang:1.27.1), so
# local and CI runs agree. No post-create fetches: the engine is
# standard-library-only in M-1, so the image is all that is needed.
#
# Development only — the deployed sensor is a static binary with no
# container dependency (C1).
FROM golang:1.27.1

WORKDIR /src
