# Phantom — build, test, and check targets.
#
# Toolchain: Go 1.27.3, pinned exactly via GOTOOLCHAIN (below; go.mod sets
# the minimum, the env var the exact release). CI and .devcontainer run the
# same pinned toolchain, so local runs and CI runs agree.

GO := go

# Exact toolchain pin (T-P-07 reproducibility): every go command runs the
# same Go release everywhere — downloaded with Go's checksum verification
# when the local toolchain differs from the pinned one.
GOTOOLCHAIN := go1.27.3
export GOTOOLCHAIN

# sha256sum is absent on macOS; shasum -a 256 is the BSD fallback. Both
# print "<hash>  <file>", so cut -d' ' -f1 extracts the digest either way.
HASH := $(shell command -v sha256sum >/dev/null 2>&1 && printf 'sha256sum' || printf 'shasum -a 256')

.PHONY: all build test lint stelint-report check trace stamp mirror-diff dco coverage perf perf-inner fixtures mutate clean

all: build lint test trace mirror-diff

# -s -w removes the symbol table and DWARF. Panic traces keep function names.
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o bin/phantom ./cmd/phantom
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/phantom-verify ./cmd/phantom-verify

test:
	$(GO) test -race ./...
	GOMEMLIMIT=256MiB $(GO) test -count=1 -run '^(TestTS25|TestTP10)' ./internal/bundle

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
# staticcheck also checks the test files. gosec checks production files only.
# govulncheck v1.9.0 ignores the GOVULNDB environment variable.
# The target passes the database with -db.
# The devcontainer has no network, so it sets GOVULNDB to a local copy.
# gosec reads the GOSEC_AI_* variables and can send code to an AI service.
# The target removes these variables from the gosec environment.
# A file:// database must have a modified value in its index/db.json.
# When that value is missing, the target counts govulncheck as failed.
GOVULNDB ?= https://vuln.go.dev
# The info file records when the image fetched the file:// database copy.
# The target fails when that copy is older than the age limit in days.
# A missing info file, or one without exactly one valid fetched line,
# also counts govulncheck as failed.
# VULNDB_NOW is a time in seconds since 1970. Empty means the current time.
# VULNDB_INFO, VULNDB_MAX_AGE_DAYS and VULNDB_NOW are for tests.
VULNDB_TIME_RE := [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z
VULNDB_INFO ?= /opt/govulndb.info
VULNDB_MAX_AGE_DAYS ?= 7
VULNDB_NOW ?=

check:
	@failed=""; \
	echo "== staticcheck =="; \
	staticcheck -tests -checks all ./... || failed="$$failed staticcheck"; \
	echo "== gosec =="; \
	env -u GOSEC_AI_PROVIDER -u GOSEC_AI_API_KEY -u GOSEC_AI_BASE_URL gosec -quiet ./... || failed="$$failed gosec"; \
	echo "== govulncheck (db: $(GOVULNDB)) =="; \
	case "$(GOVULNDB)" in \
	file://*) \
		index="$(GOVULNDB:file://%=%)/index/db.json"; \
		modified=$$(sed -n 's/.*"modified" *: *"\([^"]*\)".*/\1/p' "$$index" 2>/dev/null | tr -cd '0-9A-Za-z:.+-'); \
		if [ -n "$$modified" ]; then echo "govulncheck: database modified $$modified"; \
		else echo "govulncheck: error: no modified value in $$index"; vulnfail=1; fi; \
		if [ -r "$(VULNDB_INFO)" ]; then \
			sed -n -E '/^((sha256 [0-9a-f]{64})|(fetched $(VULNDB_TIME_RE)))$$/p' "$(VULNDB_INFO)"; \
			fetched=""; \
			if [ "$$(grep -c '^fetched ' "$(VULNDB_INFO)")" = 1 ]; then \
				fetched=$$(sed -n -E 's/^fetched ($(VULNDB_TIME_RE))$$/\1/p' "$(VULNDB_INFO)"); \
			fi; \
			now="$(VULNDB_NOW)"; [ -n "$$now" ] || now=$$(date +%s); \
			limit="$(VULNDB_MAX_AGE_DAYS)"; ftime=""; \
			if [ -n "$$fetched" ]; then ftime=$$(date -u -d "$$fetched" +%s 2>/dev/null); fi; \
			bad=""; \
			for v in "$$now" "$$limit"; do \
				case "$$v" in ""|*[!0-9]*|0?*) bad=1;; esac; \
				if [ $${#v} -gt 13 ]; then bad=1; fi; \
			done; \
			fbad=""; \
			case "$$ftime" in ""|*[!0-9]*) fbad=1;; esac; \
			if [ -z "$$bad$$fbad" ]; then \
				if [ $${#ftime} -gt 13 ] || [ "$$ftime" -gt "$$now" ]; then fbad=1; fi; \
			fi; \
			if [ -n "$$bad" ]; then \
				echo "govulncheck: error: VULNDB_NOW and VULNDB_MAX_AGE_DAYS must be digits, with no leading zero, at most 13 digits"; vulnfail=1; \
			elif [ -n "$$fbad" ]; then \
				echo "govulncheck: error: cannot compute the database copy age (fetched: $$fetched); rebuild the image with a new VULNDB_FETCHED value"; vulnfail=1; \
			elif [ $$((now - ftime)) -gt $$((limit * 86400)) ]; then \
				echo "govulncheck: error: database copy is older than $$limit days; rebuild the image with a new VULNDB_FETCHED value"; vulnfail=1; \
			else echo "govulncheck: database copy age $$(((now - ftime) / 86400)) days (limit $$limit)"; fi; \
		else echo "govulncheck: error: cannot read $(VULNDB_INFO)"; vulnfail=1; fi;; \
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
	GOMEMLIMIT=256MiB $(GO) test -count=1 -run '^(TestTS25|TestTP10)' ./internal/bundle

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
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o bin/phantom-a ./cmd/phantom
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o bin/phantom-b ./cmd/phantom
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
# starts, builds included. The target installs the go wrapper before the go
# build of tools/mutatepkg. Thus the limit also applies to that build and to
# the go list of tools/mutatepkg. The limit kills the go command and its test
# binary. A stopped mutant shows as LIVED. The limit also applies to the
# baseline run. Each run starts with an empty build cache, so MUTATE_CAP
# must be larger than a full build of the package and its tests.
# The target makes one new directory in TMPDIR, with mktemp -d, and prints the
# path. It resolves TMPDIR first and makes the directory in the resolved path.
# If TMPDIR is unset or empty, the target uses /tmp. If it cannot change to
# TMPDIR, it fails (exit 1).
# The rule below applies to the resolved TMPDIR (symlinks resolved) and to
# each of its parents up to /.
# Each must have no group or other write bit. Each must have an owner that is
# root or the current user.
# The package tests refuse a checkout below a directory that breaks this rule.
# The target checks this before it makes the directory. It refuses to run
# (exit 2) if one of them breaks the rule.
# The write-bit message names TMPDIR and the parent. The owner message also
# names the uid. If the target cannot read an owner, it prints one line and
# exits 2.
# It also refuses (exit 2) if TMPDIR is the module root or is below it.
# The copy would include the run directory.
# It copies the module to src in this directory, with all files as they are.
# The copy is a tar file and its extract. It is about twice the module with
# untracked files and .git. No size check runs during the copy, the build
# of tools/mutatepkg and the pre-check. The extract and the pre-check files
# stay. Later checks count them.
# If a tar command fails, the target prints one line and fails (exit 1).
# Gremlins starts in the copy. The module root of gremlins is then the copy.
# Gremlins finds the package of a mutant from the package name of the mutated
# file. It walks up from the directory of the file to the first directory
# whose path ends with that name. If there is none, it tests the module path.
# That is the module root package, and its go test fails at once.
# Gremlins counts that failure as a kill, so every such mutant is a false
# kill. A package main (for example cmd/phantom) is such a package.
# After the copy, the target installs the go wrapper (tools/mutate-go.sh).
# Then tools/mutatepkg gives each package below PKG the same walk.
# Sometimes exactly one package gets the module path, and it is not the
# module root package. Then the wrapper replaces the module path with the
# import path of that package.
# It does this only for a last argument of a go test call that is the
# module path. The target prints the two paths.
# The wrapper adds one line to the file "replaced" in the run directory for
# each replacement. After gremlins, the target calls tools/mutatepkg with
# -check. That mode can fail the target (exit 1) with one "mutate FAIL" line
# that names the cause. There are five causes.
# The target exports MUTATE_FROM and MUTATE_TO before gremlins. The -check
# mode reads the same two variables from its environment, as the wrapper does.
# The first is a value that is not its half of the planned replacement.
# From is the text before the first space, and to is the text after it.
# Both must be empty if no replacement is planned.
# The second is a planned replacement, with no regular file "replaced", and a
# mutant status in the gremlins output. That status is KILLED, LIVED,
# TIMED OUT or NOT VIABLE. Then no mutant ran on the package that
# tools/mutatepkg found.
# The third is a missing or repeated summary line. The "Killed, Lived" line
# and the "Timed out, Not viable" line must each be there once, after the line
# "Mutation testing completed". Then the counts are unknown.
# The fourth is Killed, Lived and Timed out all 0 and Not viable not 0.
# The fifth is a test-output file in the run directory with the FAIL line of
# a setup failure. Then the package could not load. A mutation of code does
# not change the imports. The pre-check and the coverage run of gremlins also
# write these files. They passed, so they have no such line.
# Gremlins counts exit status 1 of go test as a kill. This is also so when go
# could not load or build the package. A go vet failure in go test is also a
# build failure. For a go test call, the wrapper keeps the output in a file
# in the run directory. The file name has its process ID. Sometimes go exits
# 1, and a line of the output is the FAIL line of a setup or build failure.
# Then the wrapper exits 2 instead of 1. Gremlins counts status 2 as NOT VIABLE.
# The target refuses PKG (exit 2) before gremlins starts in some cases. Then
# it names the packages, because it cannot know the package of a mutant.
# One case is two or more packages that get the module path. The module root
# package counts. The other case is a package that gets a parent directory.
# It also refuses PKG when the first line of go.mod is not "module " and the
# module path. gremlins reads the module name from that line. A comment on
# it breaks the match. It exits 1 if go list fails or no package matches PKG.
# A PKG that gremlins already maps right has no replacement. An example is
# internal/config. Its mutants test the same package as before.
# Before gremlins starts, the target runs go test on PKG in the copy. If the
# tests fail, it prints the output and fails (exit 1) before any mutation.
# It sets TMPDIR and GOTMPDIR to the run directory. It sets GOCACHE and HOME
# to two directories in it. The caller values of these variables do not
# apply to the run.
# The target unsets XDG_CACHE_HOME, XDG_CONFIG_HOME, XDG_STATE_HOME and
# XDG_DATA_HOME.
# Then os.UserCacheDir and os.UserConfigDir give paths in HOME.
# The target keeps the caller GOPATH, GOMODCACHE and GOENV. If go env gives
# an empty GOENV, the target sets GOENV to off, so go uses no go env file.
# The target adds -count=1 to the caller GOFLAGS, read with go env GOFLAGS.
# This turns the test cache off. For each passing run, go test keeps a large
# test log in GOCACHE. The log names the files that the tests open.
# The module cache is outside the directory, so the size does not include it.
# A check once each second compares the size of this directory with
# MUTATE_MAX_MIB MiB. If the size is larger, the target stops gremlins and
# fails. The directory can grow past the limit before the run stops.
# The target checks the size once more after gremlins ends. It fails if the
# size is larger than the limit.
# The target prints the largest size that these checks saw, in MiB.
# The size does not include deleted files that a process still holds open.
# It does not include files that a test writes to an absolute path.
# MUTATE_CAP and MUTATE_MAX_MIB must be positive integers (exit 2 if not).
# The target fails (exit 1) when go or setsid is not in PATH. It also fails
# (exit 1) when go env fails or gives an empty GOPATH or GOMODCACHE.
# Before the final check and before the removal, the target makes each
# directory in the run directory writable. It does not follow links.
# It does not change the mode of a file.
# It uses names relative to each directory, so a long path works.
# It runs find with a fixed PATH, because find refuses -execdir when PATH
# has a relative or an empty entry.
# The target removes the directory on EXIT, HUP, INT, QUIT and TERM.
# The cleanup ignores these four signals, also after a normal end. Thus a
# signal does not stop the removal. It sends KILL to every process in the
# session of gremlins, so a stopped process does not block the removal.
# The go commands that gremlins starts have no run directory in their
# arguments. So pkill -f "$d/" does not find them. The session KILL does.
# The target then tries the removal up to 50 times, 0.1 s apart. If the
# directory is still there, it prints one line that names it.
# After a normal end, this line does not change the exit status (0).
# A KILL of the recipe shell leaves the run directory. A KILL of the make
# process group (for example timeout -s KILL make) also leaves it.
# There are two sessions, the first go test and then gremlins. Each has its
# own watcher.
# The watcher sees that the shell is gone. The session then stops within
# about one second.
# A KILL of the make pid alone does not stop the recipe shell. The run goes on
# and ends as normal.
# MUTATE_EXCLUDE is a list of regular expressions, separated by spaces, tabs
# or newlines. It is empty by default.
# Each entry becomes one --exclude-files=<entry> argument.
# If the value is not empty, the target prints it before gremlins starts.
# Gremlins matches an entry against the file path relative to PKG.
# The match is not anchored, so use ^ and $ for a whole name.
# The shell does not expand or split an entry. Write "$$" for a "$" on the
# make command line, because make reads a "$" and the text after it as a
# variable reference. In the environment, write a single "$".
# An entry that does not compile makes gremlins fail, so the target fails.
# The make all target does not run this target.
# Example: make mutate PKG=./internal/tlog MUTATE_EXCLUDE='^spool ^store'
MUTATE_CAP ?= 600
MUTATE_MAX_MIB ?= 10240
MUTATE_EXCLUDE ?=
export MUTATE_CAP MUTATE_MAX_MIB MUTATE_EXCLUDE
# mutate_session is internal. A value on the command line cannot replace it.
override mutate_session = setsid sh -c 'p=$$1; s=$$$$; shift; ( while kill -0 $$p 2>/dev/null; do sleep 1; done; pkill -KILL -s $$s ) & exec "$$@"' sh $$$$
mutate:
	@[ -n "$$PKG" ] || { echo "usage: make mutate PKG=./internal/<pkg>" >&2; exit 2; }
	@case "$$PKG" in -*|*[!A-Za-z0-9_./-]*) echo "mutate: PKG must use only [A-Za-z0-9_./-] and must not start with -" >&2; exit 2;; esac
	@for v in "$$MUTATE_CAP" "$$MUTATE_MAX_MIB"; do case "$$v" in ""|0*|*[!0-9]*|???????????*) echo "mutate: MUTATE_CAP and MUTATE_MAX_MIB must be positive integers of at most 10 digits" >&2; exit 2;; esac; done
	@t=$$(cd "$${TMPDIR:-/tmp}" && pwd -P) && [ -n "$$t" ] || { echo "mutate: cannot resolve TMPDIR" >&2; exit 1; }; \
	q=$$t; u=$$(id -u); while :; do \
		case "$$(ls -ldL "$$q" | cut -c6,9)" in *w*) echo "mutate: TMPDIR $$t: parent $$q has a group or other write bit; set TMPDIR to a private directory" >&2; exit 2;; esac; \
		o=$$(stat -c %u "$$q" 2>/dev/null || stat -f %u "$$q" 2>/dev/null); case "$$o" in ""|*[!0-9]*) echo "mutate: cannot read the owner of $$q" >&2; exit 2;; esac; \
		case "$$o" in 0|"$$u") ;; *) echo "mutate: TMPDIR $$t: parent $$q has owner uid $$o, not root or the current user; set TMPDIR to a private directory" >&2; exit 2;; esac; \
		[ "$$q" != / ] || break; q=$$(dirname "$$q"); done; \
	mr=$$(pwd -P); case "$$t/" in "$$mr"/*) echo "mutate: TMPDIR $$t is the module root or below it; set TMPDIR to a directory outside it" >&2; exit 2;; esac; \
	d=$$(mktemp -d "$$t/tmp.XXXXXXXXXX") || exit 1; g=; w=; \
	trap 'trap "" HUP INT QUIT TERM; kill $$g $$w 2>/dev/null; [ -z "$$g" ] || pkill -KILL -s $$g; pkill -KILL -f "$$d/"; kill -KILL $$g 2>/dev/null; wait; n=0; while [ -e "$$d" ]; do [ $$n -lt 50 ] || break; PATH=/usr/bin:/bin find "$$d" -type d ! -perm -u=rwx -execdir chmod u+rwx {} \; 2>/dev/null; rm -rf "$$d"; n=$$((n + 1)); [ ! -e "$$d" ] || sleep 0.1; done; [ ! -e "$$d" ] || echo "mutate: run directory $$d is still there after 50 tries" >&2' EXIT; \
	trap 'trap "" HUP INT QUIT TERM; exit 129' HUP; trap 'trap "" HUP INT QUIT TERM; exit 130' INT; \
	trap 'trap "" HUP INT QUIT TERM; exit 131' QUIT; trap 'trap "" HUP INT QUIT TERM; exit 143' TERM; \
	go=$$(command -v go); [ -n "$$go" ] || { echo "mutate: go is not in PATH" >&2; exit 1; }; \
	command -v setsid >/dev/null || { echo "mutate: setsid is not in PATH" >&2; exit 1; }; \
	gopath=$$("$$go" env GOPATH) && gomodcache=$$("$$go" env GOMODCACHE) && goenv=$$("$$go" env GOENV) && goflags=$$("$$go" env GOFLAGS) || { echo "mutate: go env failed" >&2; exit 1; }; \
	[ -n "$$gopath" ] && [ -n "$$gomodcache" ] || { echo "mutate: go env gives an empty GOPATH or GOMODCACHE" >&2; exit 1; }; \
	[ -n "$$goenv" ] || goenv=off; \
	mkdir "$$d/bin"; mkdir "$$d/home"; unset XDG_CACHE_HOME XDG_CONFIG_HOME XDG_STATE_HOME XDG_DATA_HOME; export GOPATH="$$gopath" GOMODCACHE="$$gomodcache" GOENV="$$goenv" GOFLAGS="$${goflags:+$$goflags }-count=1" MUTATE_GO="$$go" MUTATE_RUN="$$d" HOME="$$d/home" TMPDIR="$$d" GOTMPDIR="$$d" GOCACHE="$$d/cache" PATH="$$d/bin:$$PATH"; \
	echo "mutate: run directory $$d"; \
	echo "mutate: time limit $$MUTATE_CAP s for each go command; size limit $$MUTATE_MAX_MIB MiB, checked each second"; \
	mkdir "$$d/src" && tar -cf "$$d/m.tar" . && tar -xf "$$d/m.tar" -C "$$d/src" && rm "$$d/m.tar" || { echo "mutate FAIL: the copy of the module failed (status $$?), no test done" >&2; exit 1; }; \
	cp "$$d/src/tools/mutate-go.sh" "$$d/bin/go" && chmod +x "$$d/bin/go" || { echo "mutate FAIL: cannot install the go wrapper" >&2; exit 1; }; \
	( cd "$$d/src" && go build -buildvcs=false -o "$$d/mutatepkg" ./tools/mutatepkg ) || { echo "mutate FAIL: cannot build tools/mutatepkg" >&2; exit 1; }; \
	fix=$$( cd "$$d/src" && "$$d/mutatepkg" "$$PKG" ) || exit $$?; \
	export MUTATE_FROM="$${fix% *}" MUTATE_TO="$${fix#* }"; \
	[ -z "$$fix" ] || echo "mutate: gremlins maps the package of a mutant to $$MUTATE_FROM, so the go wrapper replaces it with $$MUTATE_TO"; \
	( cd "$$d/src" && exec $(mutate_session) go test "$$PKG" ) >"$$d/pre" 2>&1 & g=$$!; wait $$g; rc=$$?; pkill -KILL -s $$g; g=; \
	if [ "$$rc" -ne 0 ]; then cat "$$d/pre"; echo "mutate FAIL: go test $$PKG failed in the copy (status $$rc), no mutation done" >&2; exit 1; fi; \
	[ -z "$$MUTATE_EXCLUDE" ] || printf 'mutate: files excluded by MUTATE_EXCLUDE: %s\n' "$$MUTATE_EXCLUDE"; \
	set -f; set --; for e in $$MUTATE_EXCLUDE; do set -- "$$@" "--exclude-files=$$e"; done; set +f; \
	( cd "$$d/src" && exec $(mutate_session) gremlins unleash "$$PKG" "$$@" --workers 4 --timeout-coefficient 100 --invert-logical --invert-assignments --remove-self-assignments ) >"$$d/out" 2>&1 & g=$$!; \
	( m=0; while kill -0 $$g 2>/dev/null && sleep 1; do s=$$(du -sk "$$d" 2>/dev/null | cut -f1); s=$${s:-0}; \
	if [ "$$s" -gt "$$m" ]; then m=$$s; echo "$$m" >"$$d/peak"; fi; \
	if [ "$$s" -gt $$((MUTATE_MAX_MIB * 1024)) ]; then : >"$$d/full"; kill $$g; pkill -KILL -s $$g; pkill -KILL -f "$$d/"; break; fi; done ) & w=$$!; \
	wait $$g; rc=$$?; pkill -KILL -s $$g; g=; kill $$w 2>/dev/null; wait $$w 2>/dev/null; w=; \
	PATH=/usr/bin:/bin find "$$d" -type d ! -perm -u=rwx -execdir chmod u+rwx {} \; 2>/dev/null; s=$$(du -sk "$$d" 2>/dev/null | cut -f1); s=$${s:-0}; p=$$(cat "$$d/peak" 2>/dev/null); p=$${p:-0}; \
	if [ "$$s" -gt "$$p" ]; then p=$$s; fi; \
	if [ "$$s" -gt $$((MUTATE_MAX_MIB * 1024)) ]; then : >"$$d/full"; fi; \
	cat "$$d/out"; [ -z "$$(tail -c 1 "$$d/out")" ] || echo; \
	echo "mutate: largest size of the run directory: $$(( ($$p + 1023) / 1024 )) MiB"; \
	[ -e "$$d/capped" ] && echo "mutate: go commands stopped at the time limit of $$MUTATE_CAP s: $$(wc -l <"$$d/capped")" >&2; \
	if [ -e "$$d/full" ]; then echo "mutate FAIL: files are larger than $$MUTATE_MAX_MIB MiB" >&2; exit 1; fi; \
	if [ "$$rc" -ne 0 ]; then echo "mutate FAIL: gremlins exited with status $$rc" >&2; exit "$$rc"; fi; \
	grep -q 'Mutation testing completed' "$$d/out" || { echo "mutate FAIL: gremlins stopped before the end of the run" >&2; exit 1; }; \
	"$$d/mutatepkg" -check "$$d" "$$fix" || exit $$?; \
	echo "== not killed =="; \
	grep -E '^ *(LIVED|TIMED OUT) ' "$$d/out" | sed -e 's/^ */not killed: /'; \
	sed -n 's/.*\(Not covered: [0-9]*\).*/\1/p' "$$d/out" | head -n 1

clean:
	rm -rf bin cover*.out
