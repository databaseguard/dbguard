// Package pii - Shannon entropy scoring used to gate secret-like patterns.
package pii

import "math"

// Shannon returns the Shannon entropy of s in bits per byte. Random
// base64-style credentials score near 5-6; natural language near 3.5-4.5.
// An empty input scores 0.
//
// The detector uses this to accept or reject hits of loose "secret-like"
// patterns (see Pattern.entropyGate) against config.PIIConfig's
// EntropyThreshold, keeping precision high without hard-coding formats.
func Shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
