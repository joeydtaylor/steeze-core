package auth

import "encoding/base64"

func first(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func bytesToInt(b []byte) int {
	// little helper for RSA exponent
	n := 0
	for _, v := range b {
		n = n<<8 | int(v)
	}
	if n == 0 {
		return 65537
	}
	return n
}
