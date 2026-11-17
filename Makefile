# DBGuard - Makefile
#
# Build the eBPF objects and the Go control plane.
#
#   make            -> build everything
#   make bpf        -> compile eBPF objects into build/bpf
#   make go-build   -> build Go binaries into build/bin
#   make test       -> run Go unit tests
#   make demo       -> run the local attack-simulation demo (needs DBs)
#
# Requirements: clang >= 11 (BPF target), llvm-strip, go >= 1.22,
#               linux headers (linux-libc-dev), root for attach.

SHELL          := /bin/bash
GO             ?= go
CLANG          ?= clang
LLVM_STRIP     ?= llvm-strip
ARCH           ?= $(shell uname -m)

ifeq ($(ARCH),x86_64)
  BPF_ARCH      := x86
else ifeq ($(ARCH),aarch64)
  BPF_ARCH      := arm64
else
  BPF_ARCH      := x86
endif

ifeq ($(ARCH),x86_64)
MULTIARCH := x86_64-linux-gnu
else
MULTIARCH := aarch64-linux-gnu
endif

VERSION        ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
COMMIT         ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")

ROOT           := $(CURDIR)
BPFDIR         := $(ROOT)/bpf
OUT            := $(ROOT)/build
BPFOBJ         := $(OUT)/bpf
BINDIR         := $(OUT)/bin

BPF_CFLAGS := -O2 -g -Wall -Werror -Wno-comment                 \
	-target bpf                                     \
	-D__TARGET_ARCH_$(BPF_ARCH)                     \
	-DBGUARD_VERSION=\"$(VERSION)\"                 \
	-I$(BPFDIR)/include                             \
	-idirafter /usr/include -idirafter /usr/include/$(MULTIARCH)                         \
	-fno-stack-protector

BPF_SRCS := $(wildcard $(BPFDIR)/src/*.bpf.c)
BPF_OBJS := $(patsubst $(BPFDIR)/src/%.bpf.c,$(BPFOBJ)/%.bpf.o,$(BPF_SRCS))

GO_LDFLAGS := -s -w \
	-X github.com/databaseguard/dbguard/internal/version.Version=$(VERSION) \
	-X github.com/databaseguard/dbguard/internal/version.Commit=$(COMMIT)

.PHONY: all bpf go-build fmt vet test clean install zip demo docker run test-all dbgsym verify-capture  live-demo test-engines test-features test-firewall test-microseg verdicts demo-rule demo-rate

all: bpf go-build

$(BPFOBJ):
	mkdir -p $(BPFOBJ)

$(BPFOBJ)/%.bpf.o: $(BPFDIR)/src/%.bpf.c | $(BPFOBJ)
	@echo "  BPF   $<"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	-$(LLVM_STRIP) -g $@

bpf: $(BPF_OBJS) $(BPFOBJ)/rids_lsm.bpf.o $(BPFOBJ)/tenant_guard_lsm.bpf.o
	@echo "eBPF objects:" && ls -l $(BPFOBJ)

$(BPFOBJ)/rids_lsm.bpf.o: $(BPFDIR)/src/rids.bpf.c | $(BPFOBJ)
	@echo "  BPF   $< (LSM variant)"
	$(CLANG) $(BPF_CFLAGS) -DDBGUARD_ENABLE_LSM -c $< -o $@
	-$(LLVM_STRIP) -g $@

$(BPFOBJ)/tenant_guard_lsm.bpf.o: $(BPFDIR)/src/tenant_guard.bpf.c | $(BPFOBJ)
	@echo "  BPF   $< (LSM variant)"
	$(CLANG) $(BPF_CFLAGS) -DDBGUARD_ENABLE_LSM -c $< -o $@
	-$(LLVM_STRIP) -g $@

go-build:
	@echo "  GO    dbguardd, dbguard-cli"
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(GO_LDFLAGS)" -o $(BINDIR)/dbguardd ./cmd/dbguardd
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(GO_LDFLAGS)" -o $(BINDIR)/dbguard-cli ./cmd/dbguard-cli

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test -race -count=1 ./internal/... ./pkg/... 2>/dev/null || $(GO) test -count=1 ./internal/...

install: all
	install -m 0755 $(BINDIR)/dbguardd /usr/local/bin/dbguardd
	install -m 0755 $(BINDIR)/dbguard-cli /usr/local/bin/dbguard-cli
	install -d /var/lib/dbguard/bpf /etc/dbguard
	rm -f /var/lib/dbguard/bpf/*.bpf.o
	install -m 0644 $(BPFOBJ)/*.bpf.o /var/lib/dbguard/bpf/
	[ -f configs/dbguard.yaml ] && cp -n configs/dbguard.yaml /etc/dbguard/ || true
	[ -d configs/policies ] && cp -rn configs/policies /etc/dbguard/ || true

demo: go-build
	./scripts/demo.sh

# Run straight from the repo against freshly-built objects - no `make install`,
# no stale /var/lib objects. Requires root (eBPF attach).
run: go-build bpf
	sudo ./build/bin/dbguardd -config configs/dbguard.dev.yaml

# Comprehensive detection tests. Offline tier needs only the CLI; live tier
# needs the daemon + seeded DBs (scripts/setup-dbs.sh); unit tier needs the
# toolchain. Runs whatever is possible. See scripts/test-all.sh.
test-all: go-build
	./scripts/test-all.sh auto

# Install the DB debug symbols that make the query-auditing uprobes attachable
# on stripped distro binaries (enables live SQLi/PII detection).
dbgsym:
	@./scripts/install-dbgsym.sh

# Prove the query-capture -> SQLi/PII detection path end to end (needs root).
verify-capture: bpf
	sudo ./scripts/verify-capture.sh

# One-command live run: background daemon -> attacks -> show detections -> stop.
# No terminal juggling. Needs root + seeded DBs (scripts/setup-dbs.sh).
live-demo: go-build bpf
	sudo ./scripts/live-demo.sh

# Per-engine + per-feature detection test with an honest verdict (needs root + DBs).
test-engines: go-build bpf
	sudo ./scripts/test-engines.sh

# ONE script, every feature: detectors, query firewall, rate limiting, unit,
# verifier, and live end-to-end. Offline tier needs only the CLI.
test-features: go-build
	./scripts/test-features.sh auto

# Prove the query firewall: write a custom rule per matcher, verify each
# enforces exactly as configured (allow/deny/user/source/engine/db/allowlist).
test-firewall: go-build
	./scripts/test-firewall.sh

# Verify the eBPF/Cilium network micro-segmentation feature (XDP + sockmap).
test-microseg: go-build bpf
	sudo ./scripts/test-microseg.sh

# Print the firewall verdict (ALLOW/DENY + rule) for each audited query.
verdicts:
	sudo ./scripts/show-verdicts.sh $(N) $(FILTER)

# Demo the synchronous inline proxy: denied queries never reach the DB.
proxy-demo: go-build
	@echo "Set proxy.enabled and point psql at 127.0.0.1:6432 sslmode=disable"

docker:
	docker build -t dbguard:latest -f deploy/Dockerfile .

zip:
	cd .. && zip -rq dbguard.zip dbguard -x "dbguard/build/*" -x "dbguard/.git/*"

clean:
	rm -rf $(OUT)

demo-rule: go-build bpf
	sudo ./scripts/demo-rule.sh

demo-rate: go-build bpf
	sudo ./scripts/demo-rate.sh $(LIMIT) $(WINDOW)

# Live proxy smoke test: both engines through the inline proxy (daemon must be
# running with configs/dbguard.dev.yaml; DBs seeded via scripts/setup-dbs.sh).
.PHONY: proxy-test
proxy-test:
	@echo "== Postgres (6432) =="; \
	PGPASSWORD=dbguard psql "host=127.0.0.1 port=6432 dbname=dbguard_test user=dbguard sslmode=disable" -c "SELECT id, full_name FROM customers LIMIT 3;" || true; \
	PGPASSWORD=dbguard psql "host=127.0.0.1 port=6432 dbname=dbguard_test user=dbguard sslmode=disable" -c "SELECT id, full_name FROM customers UNION SELECT id, ssn FROM customers;" || true; \
	echo "== MySQL (6433) =="; \
	mysql --get-server-public-key -h 127.0.0.1 -P 6433 -u dbguard -pdbguard dbguard_test -e "SELECT id, full_name FROM customers LIMIT 3;" || true; \
	mysql --get-server-public-key -h 127.0.0.1 -P 6433 -u dbguard -pdbguard dbguard_test -e "SELECT id, full_name FROM customers UNION SELECT id, ssn FROM customers;" || true

# Exercise every shipped policy rule (dry-run per rule + live rate-limit/proxy).
.PHONY: test-policies
test-policies:
	@bash scripts/test-policies.sh

# Prove the Cilium identity-binding feature on a single host (stub agent).
.PHONY: test-cilium
test-cilium:
	@bash scripts/test-cilium.sh
