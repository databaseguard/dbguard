// bpfload -- dbguard verifier diagnostics: load every program of each
// .bpf.o and print the kernel verifier's verdict with full logs.
//
// Phase 1 loads the whole collection (ground truth). When it fails with a
// verifier error, Phase 2 isolates each program (keeping .text subprograms,
// which are bpf-to-bpf callees) so every failing program gets its own log.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	logDir    = "/tmp/diag16_logs"
	headLines = 30
	tailLines = 70
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bpfload <obj.bpf.o> [more.bpf.o ...]")
		os.Exit(2)
	}
	_ = rlimit.RemoveMemlock()
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		fmt.Println("logdir:", err)
	}

	okObj, totalObj := 0, 0
	var failing []string

	for _, obj := range os.Args[1:] {
		base := filepath.Base(obj)
		totalObj++
		fmt.Printf("\n===== OBJECT %s =====\n", base)

		spec, err := ebpf.LoadCollectionSpec(obj)
		if err != nil {
			fmt.Printf("RESULT %s OPEN_FAIL: %v\n", base, err)
			failing = append(failing, base+" (open)")
			continue
		}
		names := make([]string, 0, len(spec.Programs))
		for n := range spec.Programs {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Printf("programs(%d): %s\n", len(names), strings.Join(names, ", "))
		for _, m := range spec.Maps {
			m.Pinning = 0 // diagnostics only: never require pre-pinned maps
		}

		// Phase 1: whole collection, ground truth.
		col, err := ebpf.NewCollectionWithOptions(spec, collOpts())
		if err == nil {
			col.Close()
			okObj++
			fmt.Printf("RESULT %s ALL_PASS (%d progs)\n", base, len(names))
			continue
		}
		fmt.Printf("RESULT %s COLLECTION_FAIL: %v\n", base, err)
		dumpVerifier(base, "collection", err)
		failing = append(failing, base+" (collection)")

		var ve *ebpf.VerifierError
		if !errors.As(err, &ve) {
			// Map/permission/BTF-level problem: per-program isolation would
			// repeat the same object-level error for every program.
			fmt.Println("NOTE: 非 verifier 错误 (map/权限/BTF), 跳过逐程序隔离")
			continue
		}

		// Phase 2: isolate programs one by one.
		for _, n := range names {
			ps := spec.Programs[n]
			if ps.SectionName == ".text" {
				fmt.Printf("NOTE %s/%s: .text 子程序 (随调用方验证), 跳过独立加载\n", base, n)
				continue
			}
			single := spec.Copy()
			for other := range single.Programs {
				if other != n && single.Programs[other].SectionName != ".text" {
					delete(single.Programs, other)
				}
			}
			fmt.Printf("\n--- prog %s | type=%s | section=%s ---\n", n, ps.Type, ps.SectionName)
			col2, err2 := ebpf.NewCollectionWithOptions(single, collOpts())
			if err2 == nil {
				col2.Close()
				fmt.Printf("RESULT %s/%s PASS (isolated)\n", base, n)
				continue
			}
			fmt.Printf("RESULT %s/%s LOAD_FAIL: %v\n", base, n, err2)
			dumpVerifier(base, n, err2)
		}
	}

	fmt.Printf("\n===== SUMMARY =====\n")
	fmt.Printf("objects fully passed: %d/%d\n", okObj, totalObj)
	if len(failing) > 0 {
		fmt.Println("failing:")
		for _, f := range failing {
			fmt.Printf("  - %s\n", f)
		}
	}
	fmt.Printf("full verifier logs: %s\n", logDir)
	if okObj < totalObj {
		os.Exit(1)
	}
}

func collOpts() ebpf.CollectionOptions {
	return ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSize: 16 << 20},
	}
}

func dumpVerifier(obj, prog string, err error) {
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		fmt.Println("(no verifier log for this error)")
		return
	}
	log := ve.Log
	fn := filepath.Join(logDir, sanitize(obj)+"__"+sanitize(prog)+".log")
	_ = os.WriteFile(fn, []byte(strings.Join(log, "\n")+"\n"), 0o644)
	fmt.Printf("VERIFIER_LOG lines=%d full=%s", len(log), fn)
	if ve.Truncated {
		fmt.Print(" TRUNCATED")
	}
	fmt.Println()
	n := len(log)
	if n <= headLines+tailLines {
		for _, l := range log {
			fmt.Println("\t" + l)
		}
		return
	}
	for _, l := range log[:headLines] {
		fmt.Println("\t" + l)
	}
	fmt.Printf("\t... [%d lines skipped] ...\n", n-headLines-tailLines)
	for _, l := range log[n-tailLines:] {
		fmt.Println("\t" + l)
	}
}

func sanitize(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '-' || c == '.') {
			b[i] = '_'
		}
	}
	return string(b)
}
