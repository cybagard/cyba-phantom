# Agent Canary — M-1 task 1.1 (09).
#
# Toolchain: Go 1.27.1, pinned exactly via GOTOOLCHAIN (below; go.mod sets
# the minimum, the env var the exact release). CI and .devcontainer run the
# same pinned toolchain, so local runs and CI runs agree.

GO := go

# Exact toolchain pin (T-P-07 reproducibility): every go command runs the
# same Go release everywhere — downloaded with Go's checksum verification
# when the local toolchain differs from the pinned one.
GOTOOLCHAIN := go1.27.1
export GOTOOLCHAIN

# sha256sum is absent on macOS; shasum -a 256 is the BSD fallback. Both
# print "<hash>  <file>", so cut -d' ' -f1 extracts the digest either way.
HASH := $(shell command -v sha256sum >/dev/null 2>&1 && printf 'sha256sum' || printf 'shasum -a 256')

.PHONY: all build test lint trace stamp mirror-diff dco coverage perf perf-inner clean

all: build lint test trace mirror-diff

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/canary ./cmd/canary

test:
	$(GO) test -race ./...

lint:
	@bad=$$(gofmt -l .); \
	if [ -n "$$bad" ]; then echo "gofmt: files need formatting:"; echo "$$bad"; exit 1; fi
	$(GO) vet ./...

# C10: regenerate spec/08 from 01 + 07 and require a byte-exact match,
# then re-hash spec/ against the sync stamp.
trace:
	$(GO) run ./tools/trace all spec

# Rotate the spec sync stamp (sync PRs only; `make trace` verifies it).
stamp:
	$(GO) run ./tools/trace stamp spec --write

# AGENTS.md C1–C10 table vs the golden spec/constitution-table.md.
mirror-diff:
	./tools/mirror-diff.sh

# DCO sign-off across a commit range: make dco BASE=<sha> HEAD=<sha>
dco:
	$(GO) run ./tools/dco $(BASE) $(HEAD)

# 07 §1 coverage gate (vacuous on internal/* in M-1; 80 % on tools/).
coverage:
	bash tools/coverage.sh

# T-P-07: two builds must hash identically; the binary is static and
# <= 25 MB, built under the 07 §2 cgroup budget (1 vCPU / 512 MB).
# systemd-run --scope runs perf-inner in the foreground, in this directory,
# with this environment, and returns its exit status. Where no systemd user
# manager is available (macOS, containers) perf runs unbounded with a note;
# PERF_REQUIRE_CGROUP=1 (set in CI) turns that into a failure.
perf:
	@if command -v systemd-run >/dev/null 2>&1 && systemd-run --user --scope --quiet true >/dev/null 2>&1; then \
		echo "perf: building under a 1 vCPU / 512 MB cgroup"; \
		systemd-run --user --scope --quiet -p MemoryMax=512M -p CPUQuota=100% -- $(MAKE) perf-inner; \
	elif [ "$${PERF_REQUIRE_CGROUP:-0}" = 1 ]; then \
		echo "perf FAIL: no systemd user manager for the cgroup budget (PERF_REQUIRE_CGROUP=1)"; exit 1; \
	else \
		echo "perf: no systemd user manager — running unbounded"; \
		$(MAKE) perf-inner; \
	fi

perf-inner:
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/canary-a ./cmd/canary
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/canary-b ./cmd/canary
	@ha=$$($(HASH) bin/canary-a 2>/dev/null | cut -d' ' -f1); \
	hb=$$($(HASH) bin/canary-b 2>/dev/null | cut -d' ' -f1); \
	if [ -z "$$ha" ] || [ -z "$$hb" ]; then \
		echo "warning: no sha256sum/shasum available — reproducibility check skipped"; \
	elif [ "$$ha" != "$$hb" ]; then \
		echo "perf FAIL: two builds hashed differently"; exit 1; \
	else \
		echo "perf: reproducible build OK ($$ha)"; \
	fi
	@if command -v readelf >/dev/null 2>&1; then \
		if readelf -d bin/canary-a 2>&1 | grep -q 'no dynamic section'; then \
			echo "perf: statically linked OK"; \
		else \
			echo "perf FAIL: binary is dynamically linked"; exit 1; \
		fi; \
	elif command -v ldd >/dev/null 2>&1; then \
		if ldd bin/canary-a 2>&1 | grep -q 'not a dynamic executable'; then \
			echo "perf: statically linked OK"; \
		else \
			echo "perf FAIL: binary is dynamically linked"; exit 1; \
		fi; \
	else \
		echo "perf: no readelf/ldd available — static-link check skipped (CGO_ENABLED=0 is the gate)"; \
	fi
	@size=$$(stat -c%s bin/canary-a 2>/dev/null || stat -f%z bin/canary-a); \
	if [ "$$size" -gt 26214400 ]; then echo "perf FAIL: binary is $${size} bytes (> 25 MB)"; exit 1; fi; \
	echo "perf: binary size $${size} bytes (<= 25 MB)"

clean:
	rm -rf bin cover*.out
