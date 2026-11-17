// Package identity - container.go detects the container runtime present on
// the host and extracts container IDs from /proc cgroup lines. It is the
// parsing half of identity.Resolver.
package identity

import (
	"os"
	"regexp"
	"strings"
)

// Well-known control sockets probed by DetectRuntime.
const (
	dockerSockPath     = "/var/run/docker.sock"
	containerdSockPath = "/run/containerd/containerd.sock"
	crioSockPath       = "/run/crio/crio.sock"
)

// Container ID patterns, evaluated in order. Order matters: a cgroup line
// can contain several candidates (e.g. "/system.slice/docker-<id>.scope"
// also ends with a bare-hex-ish segment).
var (
	reDockerPath      = regexp.MustCompile(`/docker/([0-9a-f]{64})(/|$)`)
	reDockerScope     = regexp.MustCompile(`/docker-([0-9a-f]{64})\.scope`)
	reContainerdK8s   = regexp.MustCompile(`containerd:k8s\.io/([0-9a-f]{64})`)
	reContainerdScope = regexp.MustCompile(`cri-containerd-([0-9a-f]{64})\.scope`)
	reCrioScope       = regexp.MustCompile(`crio-([0-9a-f]{64})\.scope`)
	reLibpodScope     = regexp.MustCompile(`libpod-([0-9a-f]{64})\.scope`)
	// Bare 64-hex last segment: kubepods cgroupfs layouts
	// ("/kubepods/burstable/pod<uid>/<container-id>") and Docker with
	// cgroupfs driver ("/.../<container-id>").
	reBareHex = regexp.MustCompile(`/([0-9a-f]{64})$`)
)

// DetectRuntime probes the well-known runtime control sockets and returns
// one of docker|containerd|crio|none.
func DetectRuntime() string {
	switch {
	case fileExists(dockerSockPath):
		return "docker"
	case fileExists(containerdSockPath):
		return "containerd"
	case fileExists(crioSockPath):
		return "crio"
	default:
		return "none"
	}
}

// ParseCgroupPath extracts (runtime, containerID) from one /proc/<pid>/
// cgroup line such as:
//
//	"12:pids:/system.slice/docker-abc...scope"            (v1, docker)
//	"0::/kubepods.slice/.../cri-containerd-abc...scope"   (v2, containerd)
//	"10:cpuset:/kubepods/burstable/pod<uid>/abc..."       (v1, bare id)
//	"9:cpuset:/containerd:k8s.io/abc..."                  (containerd naming)
//
// It returns ("", "") when no container ID can be extracted; for bare-hex
// layouts the runtime is guessed via DetectRuntime ("unknown" when none).
func ParseCgroupPath(line string) (string, string) {
	for _, m := range reDockerPath.FindAllStringSubmatch(line, 1) {
		return "docker", m[1]
	}
	for _, m := range reDockerScope.FindAllStringSubmatch(line, 1) {
		return "docker", m[1]
	}
	for _, m := range reContainerdK8s.FindAllStringSubmatch(line, 1) {
		return "containerd", m[1]
	}
	for _, m := range reContainerdScope.FindAllStringSubmatch(line, 1) {
		return "containerd", m[1]
	}
	for _, m := range reCrioScope.FindAllStringSubmatch(line, 1) {
		return "crio", m[1]
	}
	for _, m := range reLibpodScope.FindAllStringSubmatch(line, 1) {
		return "podman", m[1]
	}
	for _, m := range reBareHex.FindAllStringSubmatch(line, 1) {
		rt := DetectRuntime()
		if rt == "none" {
			rt = "unknown"
		}
		return rt, m[1]
	}
	return "", ""
}

// IsContainerID reports whether s looks like a full 64-hex container id.
func IsContainerID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// fileExists is a tiny helper avoiding os.Stat error dances.
func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
