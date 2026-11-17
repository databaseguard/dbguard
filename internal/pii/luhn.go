// Package pii - Luhn checksum verification for payment-card candidates.
package pii

// luhnValid reports whether s passes the Luhn checksum after stripping
// spaces and dashes. It requires 13-19 digits (the same range the
// credit_card regex matches) and rejects any non-digit residue.
//
// Standard algorithm: working right-to-left, double every second digit;
// subtract 9 from products above 9; the total must be divisible by 10.
func luhnValid(s string) bool {
	sum, digits := 0, 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		switch {
		case c == ' ' || c == '-':
			continue
		case c < '0' || c > '9':
			return false
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		digits++
		double = !double
	}
	return digits >= 13 && digits <= 19 && digits > 0 && sum%10 == 0
}
