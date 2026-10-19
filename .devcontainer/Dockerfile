# Development container: the same Go toolchain as CI (golang:1.27.2), so
# local and CI runs agree. The image holds the toolchain, the static
# analysis tools, and a copy of the Go vulnerability database.
#
# Development only — the deployed sensor is a static binary with no
# container dependency (C1).
# Pinned by digest (multi-arch index of golang:1.27.2); bump both together.
FROM golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c

# Static analysis tools (SEC-09). We pin each tool by its module
# version. go install and go get check each module against the Go
# checksum database.
ARG STATICCHECK_VERSION=v0.8.2
ARG GOSEC_VERSION=v2.29.0
ARG GOVULNCHECK_VERSION=v1.9.0
# gosec v2.29.0 requires golang.org/x/tools v0.49.0. That version
# cannot read the export data of Go 1.27, so gosec does not type-check
# most packages ("export data version 5 is greater than maximum
# supported version 4"). So we build gosec in a scratch module with
# x/tools v0.52.0. When you change the Go version or the gosec version,
# examine GOSEC_XTOOLS_VERSION too. Then make sure that gosec prints no
# "export data" error.
ARG GOSEC_XTOOLS_VERSION=v0.52.0
RUN GOBIN=/usr/local/bin CGO_ENABLED=0 go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION} \
 && GOBIN=/usr/local/bin CGO_ENABLED=0 go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION} \
 && mkdir /tmp/gosec && cd /tmp/gosec && go mod init gosec-build \
 && go get github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION} golang.org/x/tools@${GOSEC_XTOOLS_VERSION} \
 && CGO_ENABLED=0 go build -o /usr/local/bin/gosec github.com/securego/gosec/v2/cmd/gosec \
 && cd / && rm -rf /tmp/gosec && go clean -cache -modcache

# The devcontainer runs without network, so govulncheck reads a copy of
# the Go vulnerability database. The copy is not pinned: it is the
# database of the day the image layer was built. GOVULNDB names it.
RUN curl -fsSL --proto '=https' --proto-redir '=https' -o /tmp/vulndb.zip https://vuln.go.dev/vulndb.zip \
 && python3 -I -m zipfile -e /tmp/vulndb.zip /opt/govulndb \
 && rm /tmp/vulndb.zip \
 && chmod -R a+rX /opt/govulndb
ENV GOVULNDB=file:///opt/govulndb

# Tests read this variable to know that they run in this container. A test
# that needs a tool of this image fails here when the tool is absent, and
# can skip outside the container.
ENV IN_DEVCONTAINER=1

WORKDIR /src
