//go:build !linux

package podman

import (
	"errors"
	"os"

	"github.com/fpp-125/metaclaw/internal/policy"
)

func registeredEnvFile(p policy.Policy, env map[string]string) (*os.File, error) {
	for _, key := range p.EnvAllowlist {
		if _, ok := env[key]; ok {
			return nil, errors.New("anonymous container environment unavailable")
		}
	}
	return nil, nil
}
