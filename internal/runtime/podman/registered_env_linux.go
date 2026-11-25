//go:build linux

package podman

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/fpp-125/metaclaw/internal/policy"
	"golang.org/x/sys/unix"
)

var envFileKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// registeredEnvFile is anonymous and never places task values in the Podman
// process environment or argv. Unsupported env-file values fail before create.
func registeredEnvFile(p policy.Policy, env map[string]string) (*os.File, error) {
	allowed := make(map[string]bool, len(p.EnvAllowlist))
	for _, key := range p.EnvAllowlist {
		allowed[key] = true
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		if allowed[key] {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	sort.Strings(keys)
	var data strings.Builder
	for _, key := range keys {
		value := env[key]
		if !envFileKey.MatchString(key) || strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("unrepresentable container environment")
		}
		if data.Len()+len(key)+len(value)+2 > 1<<20 {
			return nil, fmt.Errorf("container environment too large")
		}
		data.WriteString(key)
		data.WriteByte('=')
		data.WriteString(value)
		data.WriteByte('\n')
	}
	fd, err := unix.MemfdCreate("metaclaw-env", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "metaclaw-env")
	if _, err = f.WriteString(data.String()); err == nil {
		_, err = f.Seek(0, 0)
	}
	if err == nil {
		_, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
