# DBGuard on Kubernetes with Cilium

## Deploy steps

    # 1. Build and load the image on the cluster (or push to your registry)
    docker build -t dbguard:latest -f deploy/Dockerfile .
    kind load docker-image dbguard:latest        # example for kind

    # 2. Apply manifests
    kubectl apply -f deploy/k8s/namespace.yaml
    kubectl apply -f deploy/k8s/rbac.yaml
    kubectl apply -f deploy/k8s/configmap.yaml
    kubectl apply -f deploy/k8s/daemonset.yaml
    kubectl apply -f deploy/k8s/service.yaml

    # 3. Verify
    kubectl -n dbguard get pods -o wide
    kubectl -n dbguard logs -l app.kubernetes.io/name=dbguard --tail=50

## What the DaemonSet requires, and why

| Setting                          | Reason                                              |
|----------------------------------|-----------------------------------------------------|
| privileged: true                 | BPF program load/attach, map pinning, perf events   |
| hostPID: true                    | uprobes must address host database processes        |
| hostNetwork: true                | sees node-local traffic; Service still exposes API  |
| hostPath /sys/kernel/debug       | tracing attach points (tracefs)                     |
| hostPath /sys/fs/bpf             | pinned maps persist across agent restarts           |
| hostPath /sys/fs/cgroup          | cgroup hooks and tenant isolation need the real tree|
| hostPath /var/run                | container runtime sockets for identity resolution   |
| tolerations: operator: Exists    | schedule on control-plane nodes too                 |
| configMap dbguard-config         | /etc/dbguard/dbguard.yaml without rebuilding images |

RBAC (`deploy/k8s/rbac.yaml`) is read-only: nodes/pods/endpoints
get/watch/list - enough to map cgroup -> container -> pod -> namespace.

## CiliumNetworkPolicy examples

`deploy/cilium/ciliumnetworkpolicy-postgres.yaml` and
`ciliumnetworkpolicy-mysql.yaml` implement allowlist segmentation:

- `endpointSelector: k8s:app=postgres` selects the protected endpoints;
  once selected, Cilium **denies by default** everything not allowed.
- ingress: only `k8s:app=api-server` pods may reach 5432/3306; the host
  entity is allowed for kubelet health probes.
- egress: DNS (kube-dns, UDP/TCP 53 with L7 DNS rule) only; a database
  that starts calling out to the internet is contained immediately.

DBGuard and Cilium are complementary: Cilium decides **who may connect**;
DBGuard decides **what the session may do** (statement-level firewall, PII
masking, exfil breaker). See deploy/cilium/hubble-notes.md for the
observation workflow.

## sockmap acceleration

`deploy/cilium/sockmap-enable.yaml` shows the pod annotation
`sockmap.accel.cilium.io/enabled: "true"`, which lets Cilium redirect
same-node socket chains through an sk_msg program (lower latency for
app -> local proxy -> DB driver chains). Caveat documented in the file:
redirected traffic can bypass cgroup_skb hooks on that hop, so enable
sockmap only where DBGuard's uprobe coverage (dispatch symbols) still
provides visibility.

## Identity flow

    cgroup id (BPF event hdr.cgroup)
      -> /proc/<pid>/cgroup            (internal/identity/container.go)
         -> container id (docker/containerd/crio patterns)
            -> HOSTNAME env / mountinfo pod UID / serviceaccount namespace
               -> pod name + namespace (internal/identity/resolver.go)
                  -> optional Cilium identity: GET :9879/v1/identity?ip=
                     (internal/identity/cilium.go, 60s cache)

The resolver is wired into the pipeline via `internal/enrich.Resolver`
(with `enrich.Cache`); per-IP Cilium ids are stored on events as
`meta.cilium_identity` when `identity.cilium_enabled: true`.
