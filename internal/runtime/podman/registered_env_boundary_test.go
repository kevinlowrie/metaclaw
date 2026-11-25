//go:build linux

package podman

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fpp-125/metaclaw/internal/policy"
	"github.com/fpp-125/metaclaw/internal/runtime/spec"
)

func TestRegisteredCreateDoesNotLetTaskRedirectRuntime(t *testing.T) {
	dir := t.TempDir()
	resultPath := filepath.Join(dir, "result")
	script := "#!/bin/sh\nprintf '%s' \"$CONTAINER_HOST\" > \"$RESULT_PATH\"\nprintf '%064d\\n' 0\n"
	if err := os.WriteFile(filepath.Join(dir, "podman"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("RESULT_PATH", resultPath)
	t.Setenv("CONTAINER_HOST", "trusted-host-setting")
	_, _ = New().RunRegistered(testContext(t), spec.RunOptions{
		ContainerName: "fixture", Image: "fixture", Env: map[string]string{"CONTAINER_HOST": "task-setting"},
	}, func(context.Context, string) error { return errors.New("stop before start") })
	b, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != "trusted-host-setting" {
		t.Fatalf("task environment changed runtime-control environment: %q", got)
	}
}

func TestRegisteredCreateSeparatesAllowedTaskEnvironment(t *testing.T) {
	dir := t.TempDir()
	resultPath := filepath.Join(dir, "result")
	envPath := filepath.Join(dir, "env")
	script := `#!/bin/sh
printf '%s' "$CONTAINER_HOST" > "$RESULT_PATH"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--env-file" ]; then cat "$2" > "$ENV_PATH"; break; fi
  shift
done
printf '%064d\n' 0
`
	if err := os.WriteFile(filepath.Join(dir, "podman"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("RESULT_PATH", resultPath)
	t.Setenv("ENV_PATH", envPath)
	t.Setenv("CONTAINER_HOST", "trusted-host-setting")
	_, _ = New().RunRegistered(testContext(t), spec.RunOptions{
		ContainerName: "fixture", Image: "fixture",
		Policy: policy.Policy{EnvAllowlist: []string{"CONTAINER_HOST", "ALLOWED"}},
		Env:    map[string]string{"CONTAINER_HOST": "container-setting", "ALLOWED": "fixture-value", "DISALLOWED": "ignored"},
	}, func(context.Context, string) error { return errors.New("stop before start") })
	runtimeValue, err := os.ReadFile(resultPath)
	if err != nil || string(runtimeValue) != "trusted-host-setting" {
		t.Fatalf("runtime control changed: %q %v", runtimeValue, err)
	}
	containerValues, err := os.ReadFile(envPath)
	if err != nil || string(containerValues) != "ALLOWED=fixture-value\nCONTAINER_HOST=container-setting\n" {
		t.Fatalf("unexpected container environment: %q %v", containerValues, err)
	}
}

func TestRegisteredCreateRejectsUnrepresentableEnvironmentBeforeCreate(t *testing.T) {
	log := fakePodman(t)
	_, err := New().RunRegistered(testContext(t), spec.RunOptions{
		ContainerName: "fixture", Image: "fixture", Policy: policy.Policy{EnvAllowlist: []string{"ALLOWED"}},
		Env: map[string]string{"ALLOWED": "line1\nline2"},
	}, func(context.Context, string) error { return nil })
	if err == nil || calls(t, log) != "" {
		t.Fatalf("err=%v calls=%q", err, calls(t, log))
	}
}
