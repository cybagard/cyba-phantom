# Development container: the same Go toolchain as CI (golang:1.27.3), so
# local and CI runs agree. The image holds the toolchain, the static
# analysis tools, a mutation test tool, and the Go vulnerability database.
#
# Development only — the deployed sensor is a static binary with no
# container dependency (C1).
# Pinned by digest (multi-arch index of golang:1.27.3); bump both together.
# The oracle job of .github/workflows/ci.yml uses the same digest.
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b

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

# The make mutate target runs the gremlins mutation test tool.
# make all does not run it. We pin the tool by its module version,
# the same as the tools above.
ARG GREMLINS_VERSION=v0.6.0
RUN GOBIN=/usr/local/bin CGO_ENABLED=0 go install github.com/go-gremlins/gremlins/cmd/gremlins@${GREMLINS_VERSION} \
 && go clean -cache -modcache

# The devcontainer runs without network, so govulncheck reads a copy of
# the Go vulnerability database. GOVULNDB names it. The source is
# vuln.go.dev, and the data has the CC BY 4.0 license.
# A build with a new VULNDB_FETCHED value fetches the latest copy. A
# build without it can use the copy of an earlier build.
# /opt/govulndb.info records the SHA-256 of the zip, the modified value
# of the index, and the download time. make check refuses an image that
# fetched its copy more than 7 days ago.
ARG VULNDB_FETCHED=
RUN echo "cache key ${VULNDB_FETCHED}" \
 && curl -fsSL --proto '=https' --proto-redir '=https' -o /tmp/vulndb.zip https://vuln.go.dev/vulndb.zip \
 && fetched=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
 && python3 -I -m zipfile -e /tmp/vulndb.zip /opt/govulndb \
 && sha=$(sha256sum /tmp/vulndb.zip | cut -d' ' -f1) \
 && test -n "$sha" \
 && modified=$(sed -n 's/.*"modified" *: *"\([^"]*\)".*/\1/p' /opt/govulndb/index/db.json | head -n 1 | tr -cd '0-9A-Za-z:.+-') \
 && test -n "$modified" \
 && printf 'sha256 %s\nmodified %s\nfetched %s\n' "$sha" "$modified" "$fetched" > /opt/govulndb.info \
 && rm /tmp/vulndb.zip \
 && chmod -R a+rX /opt/govulndb \
 && chmod a+r /opt/govulndb.info
ENV GOVULNDB=file:///opt/govulndb

# Tests read this variable to know that they run in this container. A test
# that needs a tool of this image fails here when the tool is absent, and
# can skip outside the container.
ENV IN_DEVCONTAINER=1

WORKDIR /src
