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
# with this environment, and returns its exit status. perf-inner then reads
# its own cgroup to confirm that the limits apply.
#
# Where a tool is missing (no systemd user manager, no readelf/ldd, no
# sha256 tool), perf skips that check with a note. PERF_STRICT=1 (set in
# CI) turns every skip into a failure.
PERF_STRICT ?= 0
# skip <message>: a note, or a failure under PERF_STRICT=1.
skip = if [ "$(PERF_STRICT)" = 1 ]; then echo "perf FAIL: $(1) (PERF_STRICT=1)"; exit 1; else echo "perf: $(1) — skipped"; fi

perf:
	@if command -v systemd-run >/dev/null 2>&1 && systemd-run --user --scope --quiet true >/dev/null 2>&1; then \
		echo "perf: building under a 1 vCPU / 512 MB cgroup"; \
		systemd-run --user --scope --quiet -p MemoryMax=512M -p CPUQuota=100% -- $(MAKE) perf-inner PERF_IN_CGROUP=1; \
	else \
		$(call skip,no systemd user manager for the cgroup budget); \
		$(MAKE) perf-inner; \
	fi

perf-inner:
	@if [ "$(PERF_IN_CGROUP)" = 1 ]; then \
		cg="/sys/fs/cgroup$$(sed -n 's/^0:://p' /proc/self/cgroup)"; \
		mem=$$(cat "$$cg/memory.max" 2>/dev/null); cpu=$$(cat "$$cg/cpu.max" 2>/dev/null); \
		if [ "$$mem" != 536870912 ] || [ "$$cpu" != "100000 100000" ]; then \
			echo "perf FAIL: cgroup limits not applied (memory.max=$$mem, cpu.max=$$cpu)"; exit 1; \
		fi; \
		echo "perf: cgroup limits applied (memory.max=$$mem, cpu.max=$$cpu)"; \
	fi
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/canary-a ./cmd/canary
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/canary-b ./cmd/canary
	@ha=$$($(HASH) bin/canary-a 2>/dev/null | cut -d' ' -f1); \
	hb=$$($(HASH) bin/canary-b 2>/dev/null | cut -d' ' -f1); \
	if [ -z "$$ha" ] || [ -z "$$hb" ]; then \
		$(call skip,no sha256sum/shasum for the reproducibility check); \
	elif [ "$$ha" != "$$hb" ]; then \
		echo "perf FAIL: two builds hashed differently"; exit 1; \
	else \
		echo "perf: reproducible build OK ($$ha)"; \
	fi
	@if command -v readelf >/dev/null 2>&1; then \
		dyn=$$(readelf -d bin/canary-a 2>&1 | grep -c 'no dynamic section'); \
	elif command -v ldd >/dev/null 2>&1; then \
		dyn=$$(ldd bin/canary-a 2>&1 | grep -c 'not a dynamic executable'); \
	else \
		$(call skip,no readelf/ldd for the static-link check); exit 0; \
	fi; \
	if [ "$$dyn" -ge 1 ]; then echo "perf: statically linked OK"; \
	else echo "perf FAIL: binary is dynamically linked"; exit 1; fi
	@size=$$(stat -c%s bin/canary-a 2>/dev/null || stat -f%z bin/canary-a 2>/dev/null); \
	if [ -z "$$size" ]; then $(call skip,no stat for the size check); exit 0; fi; \
	if [ "$$size" -gt 26214400 ]; then echo "perf FAIL: binary is $${size} bytes (> 25 MB)"; exit 1; fi; \
	echo "perf: binary size $${size} bytes (<= 25 MB)"

clean:
	rm -rf bin cover*.out
