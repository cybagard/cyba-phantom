# Phantom — build, test, and check targets.
#
# Toolchain: Go 1.27.2, pinned exactly via GOTOOLCHAIN (below; go.mod sets
# the minimum, the env var the exact release). CI and .devcontainer run the
# same pinned toolchain, so local runs and CI runs agree.

GO := go

# Exact toolchain pin (T-P-07 reproducibility): every go command runs the
# same Go release everywhere — downloaded with Go's checksum verification
# when the local toolchain differs from the pinned one.
GOTOOLCHAIN := go1.27.2
export GOTOOLCHAIN

# sha256sum is absent on macOS; shasum -a 256 is the BSD fallback. Both
# print "<hash>  <file>", so cut -d' ' -f1 extracts the digest either way.
HASH := $(shell command -v sha256sum >/dev/null 2>&1 && printf 'sha256sum' || printf 'shasum -a 256')

.PHONY: all build test lint stelint-report check trace stamp mirror-diff dco coverage perf perf-inner fixtures mutate clean

all: build lint test trace mirror-diff

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/phantom ./cmd/phantom
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/phantom-verify ./cmd/phantom-verify

test:
	$(GO) test -race ./...
	GOMEMLIMIT=256MiB $(GO) test -count=1 -run '^TestTS25' ./internal/bundle

lint:
	@bad=$$(gofmt -l .) || { echo "gofmt: gofmt -l . failed"; exit 1; }; \
	if [ -n "$$bad" ]; then echo "gofmt: $$(echo "$$bad" | wc -l | tr -d ' ') file(s) need formatting; run gofmt -l . locally"; exit 1; fi
	$(GO) vet ./...
	@base="$(BASE)"; head="$(or $(HEAD),HEAD)"; \
	if [ -z "$$base" ] && git rev-parse --verify -q origin/main >/dev/null; then \
		base=$$(git merge-base origin/main "$$head") || { echo "lint: git merge-base origin/main $$head failed"; exit 1; }; \
	fi; \
	$(GO) run ./tools/stelint "$$base" "$$head"

# This target lists the comment lines over 80 columns in the tracked Go files
# at HEAD. It also lists the comment sentences over 20 words. The HEAD
# variable selects another commit. It skips files below testdata. It prints
# each hit and a total for each rule. It exits 0 unless git or an input limit
# fails.
# The lint target checks the comment lines that changed between BASE and HEAD.
# It also checks a sentence that has a changed line, or that a deletion joins.
stelint-report:
	$(GO) run ./tools/stelint -all "$(or $(HEAD),HEAD)"

# The check target runs staticcheck, gosec and govulncheck on the module.
# All three tools run on every call. Each tool prints under its own header line.
# The target fails when any tool fails, and it names the failed tools.
# The target is not part of all.
# govulncheck v1.9.0 ignores the GOVULNDB environment variable.
# The target passes the database with -db.
# The devcontainer has no network, so it sets GOVULNDB to a local copy.
# gosec reads the GOSEC_AI_* variables and can send code to an AI service.
# The target removes these variables from the gosec environment.
# A file:// database must have a modified value in its index/db.json.
# When that value is missing, the target counts govulncheck as failed.
GOVULNDB ?= https://vuln.go.dev

check:
	@failed=""; \
	echo "== staticcheck =="; \
	staticcheck ./... || failed="$$failed staticcheck"; \
	echo "== gosec =="; \
	env -u GOSEC_AI_PROVIDER -u GOSEC_AI_API_KEY -u GOSEC_AI_BASE_URL gosec -quiet ./... || failed="$$failed gosec"; \
	echo "== govulncheck (db: $(GOVULNDB)) =="; \
	case "$(GOVULNDB)" in \
	file://*) \
		index="$(GOVULNDB:file://%=%)/index/db.json"; \
		modified=$$(sed -n 's/.*"modified" *: *"\([^"]*\)".*/\1/p' "$$index" 2>/dev/null | tr -cd '0-9A-Za-z:.+-'); \
		if [ -n "$$modified" ]; then echo "govulncheck: database modified $$modified"; \
		else echo "govulncheck: error: no modified value in $$index"; vulnfail=1; fi;; \
	esac; \
	govulncheck -db "$(GOVULNDB)" ./... || vulnfail=1; \
	if [ -n "$$vulnfail" ]; then failed="$$failed govulncheck"; fi; \
	if [ -n "$$failed" ]; then echo "check FAIL:$$failed"; exit 1; fi; \
	echo "check: staticcheck, gosec and govulncheck passed"

# The current milestone of 07 section 5. A PR changes this value when a
# milestone gate closes. CI reads this line with sed: keep the form.
TRACE_MILESTONE := M-1

# C10: regenerate spec/08 from 01 + 07 and require a byte-exact match,
# then re-hash spec/ against the sync stamp. Then require a Go test or a
# Makefile marker for each test ID of the milestones up to TRACE_MILESTONE.
trace:
	$(GO) run ./tools/trace all spec
	$(GO) run ./tools/trace tests spec --milestone $(TRACE_MILESTONE)

# Rotate the spec sync stamp (sync PRs only; `make trace` verifies it).
stamp:
	$(GO) run ./tools/trace stamp spec --write

# AGENTS.md C1–C10 table vs the golden spec/constitution-table.md.
mirror-diff:
	./tools/mirror-diff.sh

# DCO sign-off and commit identity across a commit range: make dco BASE=<sha> HEAD=<sha>
dco:
	$(GO) run ./tools/dco $(BASE) $(HEAD)

# 07 §1 coverage gate (vacuous on internal/* in M-1; 80 % on tools/).
coverage:
	bash tools/coverage.sh
	GOMEMLIMIT=256MiB $(GO) test -count=1 -run '^TestTS25' ./internal/bundle

# T-U-06: write the sha256 values of the hand-written canonical text into
# internal/event/testdata. T-U-12: write the signed note into the golden
# section of internal/tlog/verifier/testdata/notes.txt. Nobody edits those values by
# hand (test/README). T-U-08: write the bundle files into test/fixtures/bundles.
fixtures:
	$(GO) test ./internal/event -run TestTU06 -update
	$(GO) test ./internal/tlog/verifier -run TestTU12_Golden -update
	$(GO) test ./internal/bundle -run TestTU08FixturesAreCurrent -update

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

# trace-test: T-P-07 perf
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
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/phantom-a ./cmd/phantom
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/phantom-b ./cmd/phantom
	@ha=$$($(HASH) bin/phantom-a 2>/dev/null | cut -d' ' -f1); \
	hb=$$($(HASH) bin/phantom-b 2>/dev/null | cut -d' ' -f1); \
	if [ -z "$$ha" ] || [ -z "$$hb" ]; then \
		$(call skip,no sha256sum/shasum for the reproducibility check); \
	elif [ "$$ha" != "$$hb" ]; then \
		echo "perf FAIL: two builds hashed differently"; exit 1; \
	else \
		echo "perf: reproducible build OK ($$ha)"; \
	fi
	@if command -v readelf >/dev/null 2>&1; then \
		static=$$(readelf -d bin/phantom-a 2>&1 | grep -c 'no dynamic section'); \
	elif command -v ldd >/dev/null 2>&1; then \
		static=$$(ldd bin/phantom-a 2>&1 | grep -c 'not a dynamic executable'); \
	else \
		$(call skip,no readelf/ldd for the static-link check); exit 0; \
	fi; \
	if [ "$$static" -ge 1 ]; then echo "perf: statically linked OK"; \
	else echo "perf FAIL: binary is dynamically linked"; exit 1; fi
	@size=$$(stat -c%s bin/phantom-a 2>/dev/null || stat -f%z bin/phantom-a 2>/dev/null); \
	if [ -z "$$size" ]; then $(call skip,no stat for the size check); exit 0; fi; \
	if [ "$$size" -gt 26214400 ]; then echo "perf FAIL: binary is $${size} bytes (> 25 MB)"; exit 1; fi; \
	echo "perf: binary size $${size} bytes (<= 25 MB)"

# The target runs gremlins mutation tests on the package in PKG. It prints
# the gremlins output. Then it prints each mutant that tests did not kill,
# with its status, mutator and position. It also prints the Not covered count.
# It does not fail on the efficacy value. It fails when PKG is empty.
# It refuses a PKG that starts with "-" or has a character outside
# [A-Za-z0-9_./-] (exit 2). It fails when gremlins exits with a status
# that is not 0. It also fails when the gremlins output has no
# "Mutation testing completed" line. Gremlins exits 0 after a signal,
# so the completion line shows a full run.
# MUTATE_CAP is the time limit in seconds for each go command that gremlins
# starts, builds included. The limit kills the go command and its test
# binary. A stopped mutant shows as LIVED. The limit also applies to the
# baseline run. Each run starts with an empty build cache, so MUTATE_CAP
# must be larger than a full build of the package and its tests.
# The target makes one new directory in the caller TMPDIR. It sets TMPDIR
# and GOTMPDIR to this directory. It sets GOCACHE and HOME to two
# directories in it. The caller values of these variables do not apply to
# the run.
# The target unsets XDG_CACHE_HOME, XDG_CONFIG_HOME, XDG_STATE_HOME and
# XDG_DATA_HOME.
# Then os.UserCacheDir and os.UserConfigDir give paths in HOME.
# The target keeps the caller GOPATH, GOMODCACHE and GOENV. If go env gives
# an empty GOENV, the target sets GOENV to off, so go uses no go env file.
# The module cache is outside the directory, so the size does not include it.
# A check once each second compares the size of this directory with
# MUTATE_MAX_MIB MiB. If the size is larger, the target stops gremlins and
# fails. The directory can grow past the limit before the run stops.
# The target checks the size once more after gremlins ends. It fails if the
# size is larger than the limit.
# The target prints the largest size that these checks saw, in MiB.
# The size does not include deleted files that a process still holds open.
# It does not include files that a test writes to an absolute path.
# It does not include files that a test writes to a relative path in the
# baseline run. That run has the package source directory as its working
# directory.
# MUTATE_CAP and MUTATE_MAX_MIB must be positive integers (exit 2 if not).
# The target fails (exit 1) when go is not in PATH. It also fails (exit 1)
# when go env fails or gives an empty GOPATH or GOMODCACHE.
# Before the final check and before the removal, the target makes each
# directory in the run directory writable. It does not follow links.
# It does not change the mode of a file.
# The target removes the directory on EXIT, HUP, INT, QUIT and TERM.
# Each signal trap first ignores these signals, so a second signal does not
# stop the removal.
# The make all target does not run this target.
# Example: make mutate PKG=./internal/bundle MUTATE_CAP=60
MUTATE_CAP ?= 600
MUTATE_MAX_MIB ?= 10240
export MUTATE_CAP MUTATE_MAX_MIB
mutate:
	@[ -n "$$PKG" ] || { echo "usage: make mutate PKG=./internal/<pkg>" >&2; exit 2; }
	@case "$$PKG" in -*|*[!A-Za-z0-9_./-]*) echo "mutate: PKG must use only [A-Za-z0-9_./-] and must not start with -" >&2; exit 2;; esac
	@for v in "$$MUTATE_CAP" "$$MUTATE_MAX_MIB"; do case "$$v" in ""|0*|*[!0-9]*|???????????*) echo "mutate: MUTATE_CAP and MUTATE_MAX_MIB must be positive integers of at most 10 digits" >&2; exit 2;; esac; done
	@d=$$(mktemp -d) || exit 1; g=; w=; \
	trap 'kill $$g $$w 2>/dev/null; pkill -KILL -f "$$d/"; wait; find "$$d" -type d ! -perm -u=rwx -exec chmod u+rwx {} \; 2>/dev/null; rm -rf "$$d"' EXIT; \
	trap 'trap "" HUP INT QUIT TERM; exit 129' HUP; trap 'trap "" HUP INT QUIT TERM; exit 130' INT; \
	trap 'trap "" HUP INT QUIT TERM; exit 131' QUIT; trap 'trap "" HUP INT QUIT TERM; exit 143' TERM; \
	go=$$(command -v go); [ -n "$$go" ] || { echo "mutate: go is not in PATH" >&2; exit 1; }; \
	gopath=$$("$$go" env GOPATH) && gomodcache=$$("$$go" env GOMODCACHE) && goenv=$$("$$go" env GOENV) || { echo "mutate: go env failed" >&2; exit 1; }; \
	[ -n "$$gopath" ] && [ -n "$$gomodcache" ] || { echo "mutate: go env gives an empty GOPATH or GOMODCACHE" >&2; exit 1; }; \
	[ -n "$$goenv" ] || goenv=off; \
	mkdir "$$d/bin"; \
	printf '#!/bin/sh\ntimeout -s KILL "$$MUTATE_CAP" "$$MUTATE_GO" "$$@"\nr=$$?\ncase $$r in 124|137) echo >>"$$MUTATE_RUN/capped";; esac\nexit $$r\n' >"$$d/bin/go"; \
	chmod +x "$$d/bin/go"; mkdir "$$d/home"; unset XDG_CACHE_HOME XDG_CONFIG_HOME XDG_STATE_HOME XDG_DATA_HOME; export GOPATH="$$gopath" GOMODCACHE="$$gomodcache" GOENV="$$goenv" MUTATE_GO="$$go" MUTATE_RUN="$$d" HOME="$$d/home" TMPDIR="$$d" GOTMPDIR="$$d" GOCACHE="$$d/cache" PATH="$$d/bin:$$PATH"; \
	echo "mutate: time limit $$MUTATE_CAP s for each go command; size limit $$MUTATE_MAX_MIB MiB, checked each second"; \
	gremlins unleash "$$PKG" --workers 4 --timeout-coefficient 100 --invert-logical --invert-assignments --remove-self-assignments >"$$d/out" 2>&1 & g=$$!; \
	( m=0; while kill -0 $$g 2>/dev/null && sleep 1; do s=$$(du -sk "$$d" 2>/dev/null | cut -f1); s=$${s:-0}; \
	if [ "$$s" -gt "$$m" ]; then m=$$s; echo "$$m" >"$$d/peak"; fi; \
	if [ "$$s" -gt $$((MUTATE_MAX_MIB * 1024)) ]; then : >"$$d/full"; kill $$g; pkill -KILL -f "$$d/"; break; fi; done ) & w=$$!; \
	wait $$g; rc=$$?; g=; kill $$w 2>/dev/null; wait $$w 2>/dev/null; w=; \
	find "$$d" -type d ! -perm -u=rwx -exec chmod u+rwx {} \; 2>/dev/null; s=$$(du -sk "$$d" 2>/dev/null | cut -f1); s=$${s:-0}; p=$$(cat "$$d/peak" 2>/dev/null); p=$${p:-0}; \
	if [ "$$s" -gt "$$p" ]; then p=$$s; fi; \
	if [ "$$s" -gt $$((MUTATE_MAX_MIB * 1024)) ]; then : >"$$d/full"; fi; \
	cat "$$d/out"; [ -z "$$(tail -c 1 "$$d/out")" ] || echo; \
	echo "mutate: largest size of the run directory: $$(( ($$p + 1023) / 1024 )) MiB"; \
	[ -e "$$d/capped" ] && echo "mutate: go commands stopped at the time limit of $$MUTATE_CAP s: $$(wc -l <"$$d/capped")" >&2; \
	if [ -e "$$d/full" ]; then echo "mutate FAIL: files are larger than $$MUTATE_MAX_MIB MiB" >&2; exit 1; fi; \
	if [ "$$rc" -ne 0 ]; then echo "mutate FAIL: gremlins exited with status $$rc" >&2; exit "$$rc"; fi; \
	grep -q 'Mutation testing completed' "$$d/out" || { echo "mutate FAIL: gremlins stopped before the end of the run" >&2; exit 1; }; \
	echo "== not killed =="; \
	grep -E '^ *(LIVED|TIMED OUT) ' "$$d/out" | sed -e 's/^ */not killed: /'; \
	sed -n 's/.*\(Not covered: [0-9]*\).*/\1/p' "$$d/out" | head -n 1

clean:
	rm -rf bin cover*.out
