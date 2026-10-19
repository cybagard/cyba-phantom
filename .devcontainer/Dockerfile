# Development container: the same Go toolchain as CI (golang:1.27.2), so
# local and CI runs agree. The image holds the toolchain, the static
# analysis tools, and a copy of the Go vulnerability database.
#
# Development only — the deployed sensor is a static binary with no
# container dependency (C1).
# Pinned by digest (multi-arch index of golang:1.27.2); bump both together.
FROM golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c

# Static analysis tools (SEC-09). Each tool is pinned
# by its module version; go install checks the module against the Go
# checksum database. A bump changes one version here.
ARG STATICCHECK_VERSION=v0.8.2
ARG GOSEC_VERSION=v2.29.0
ARG GOVULNCHECK_VERSION=v1.9.0
RUN GOBIN=/usr/local/bin CGO_ENABLED=0 go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION} \
 && GOBIN=/usr/local/bin CGO_ENABLED=0 go install github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION} \
 && GOBIN=/usr/local/bin CGO_ENABLED=0 go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION} \
 && go clean -cache -modcache

# The devcontainer runs without network, so govulncheck reads a copy of
# the Go vulnerability database. The copy is not pinned: it is the
# database of the day the image layer was built. GOVULNDB names it.
RUN curl -fsSL -o /tmp/vulndb.zip https://vuln.go.dev/vulndb.zip \
 && python3 -m zipfile -e /tmp/vulndb.zip /opt/govulndb \
 && rm /tmp/vulndb.zip \
 && chmod -R a+rX /opt/govulndb
ENV GOVULNDB=file:///opt/govulndb

WORKDIR /src
