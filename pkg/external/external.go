package external

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

var ErrBinaryMissing = errors.New("external scanner binary not found on PATH")

func ResolveBinary(preferred, name string) (string, error) {
	if preferred != "" {
		if _, err := exec.LookPath(preferred); err == nil {
			return preferred, nil
		}
		return "", fmt.Errorf("%w: %q", ErrBinaryMissing, preferred)
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrBinaryMissing, name)
	}
	return p, nil
}

func trimLong(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func joinList(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ", ")
}
