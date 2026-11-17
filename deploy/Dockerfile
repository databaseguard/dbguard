# DBGuard container image.
#
# Stage 1 compiles the eBPF objects (clang/llvm against the kernel UAPI
# headers) and the Go control plane. Stage 2 is a minimal Ubuntu runtime.
#
# RUNTIME REQUIREMENTS (documented, not enforceable inside the image):
#   - The container must run with privileged: true (or CAP_BPF+CAP_PERFMON+
#     CAP_SYS_ADMIN) to load and attach BPF programs and pin maps.
#   - pid: "host" and cgroup: host are required so uprobes/cgroup hooks see
#     the host database processes.
#   - Host mounts needed: /sys/kernel (read-only), /sys/fs/bpf,
#     /sys/fs/cgroup, /var/run (runtime sockets for identity resolution).
#
# Build:  docker build -t dbguard:latest -f deploy/Dockerfile .
# Run:    see deploy/docker-compose.yml or deploy/k8s/daemonset.yaml

FROM golang:1.22-bookworm AS build

# clang >= 11 (BPF target), llvm-strip, libelf and linux-libc-dev (UAPI
# headers) are required by `make bpf`.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        clang llvm libelf-dev linux-libc-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build eBPF objects into build/bpf and Go binaries into build/bin.
RUN make bpf go-build

FROM ubuntu:24.04

# CA certificates for HTTPS webhooks/Slack; the Go binaries are
# CGO_ENABLED=0 static builds and need no other runtime libraries.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/lib/dbguard/bpf /var/lib/dbguard/audit /etc/dbguard/policies /var/log/dbguard

COPY --from=build /src/build/bin/dbguardd   /usr/local/bin/dbguardd
COPY --from=build /src/build/bin/dbguard-cli /usr/local/bin/dbguard-cli
COPY --from=build /src/build/bpf/           /var/lib/dbguard/bpf/
COPY configs/dbguard.yaml    /etc/dbguard/dbguard.yaml
COPY configs/policies/       /etc/dbguard/policies/
# Also bake policies under the data dir. In Kubernetes the `config` configMap
# mounts over /etc/dbguard and SHADOWS /etc/dbguard/policies, so the in-cluster
# policies.dirs points at /var/lib/dbguard/policies (never shadowed, writable so
# policies can be hot-reloaded by writing files into it).
COPY configs/policies/       /var/lib/dbguard/policies/

# 9700 = admin REST API, 9701 = Prometheus metrics.
EXPOSE 9700 9701

ENTRYPOINT ["/usr/local/bin/dbguardd"]
