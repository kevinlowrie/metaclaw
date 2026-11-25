package podman

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fpp-125/metaclaw/internal/runtime/spec"
)

func fakePodman(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := `#!/bin/sh
printf '%s\n' "$1" >> "$CALLS"
case "$1" in
create) if [ "$CREATE_WAIT" = 1 ]; then exec sleep 3; fi; if [ "$HOLD_PIPE" = 1 ]; then sleep 2 & fi; printf '%s\n' "$CREATED_ID"; [ "$CREATE_FAIL" != 1 ] ;;
start) if [ "$START_WAIT" = 1 ]; then exec sleep 3; fi; [ "$START_FAIL" != 1 ] ;;
run) printf 'ordinary-output' ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "podman"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("CALLS", log)
	t.Setenv("CREATED_ID", strings.Repeat("a", 64))
	return log
}
func calls(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func TestRegisteredRunAcknowledgesBeforeStart(t *testing.T) {
	log := fakePodman(t)
	id := strings.Repeat("a", 64)
	result, err := New().RunRegistered(testContext(t), spec.RunOptions{ContainerName: "test", Image: "image"}, func(_ context.Context, got string) error {
		if got != id || calls(t, log) != "create\n" {
			t.Fatalf("wrong registration identity or ordering: %q %q", got, calls(t, log))
		}
		return nil
	})
	if err != nil || result.ContainerID != id || calls(t, log) != "create\nstart\n" {
		t.Fatalf("result=%+v err=%v calls=%q", result, err, calls(t, log))
	}
}
func TestRegisteredRunNeverStartsWhenRegistrationFails(t *testing.T) {
	log := fakePodman(t)
	id := strings.Repeat("a", 64)
	result, err := New().RunRegistered(testContext(t), spec.RunOptions{ContainerName: "test", Image: "image"}, func(context.Context, string) error { return errors.New("sensitive detail") })
	if err == nil || strings.Contains(err.Error(), "sensitive detail") || result.ContainerID != id || calls(t, log) != "create\n" {
		t.Fatalf("result=%+v err=%v calls=%q", result, err, calls(t, log))
	}
}
func TestRegisteredRunCreateUnknownDoesNotStart(t *testing.T) {
	log := fakePodman(t)
	t.Setenv("CREATE_FAIL", "1")
	called := false
	result, err := New().RunRegistered(testContext(t), spec.RunOptions{ContainerName: "test", Image: "image"}, func(context.Context, string) error { called = true; return nil })
	if err == nil || !result.CreateUnknown || called || calls(t, log) != "create\n" {
		t.Fatalf("result=%+v err=%v calls=%q", result, err, calls(t, log))
	}
}
func TestRegisteredRunStartFailureIsUnknown(t *testing.T) {
	log := fakePodman(t)
	t.Setenv("START_FAIL", "1")
	result, err := New().RunRegistered(testContext(t), spec.RunOptions{ContainerName: "test", Image: "image"}, func(context.Context, string) error { return nil })
	if err == nil || !result.StartUnknown || result.ContainerID != strings.Repeat("a", 64) || calls(t, log) != "create\nstart\n" {
		t.Fatalf("result=%+v err=%v calls=%q", result, err, calls(t, log))
	}
}
func TestRunRetainsDefaultBehavior(t *testing.T) {
	log := fakePodman(t)
	r, err := New().Run(testContext(t), spec.RunOptions{ContainerName: "test", Image: "image"})
	if err != nil || r.Stdout != "ordinary-output" || calls(t, log) != "run\n" {
		t.Fatalf("result=%+v err=%v calls=%q", r, err, calls(t, log))
	}
}

func TestRegisteredRunRejectsMalformedCreateIdentity(t *testing.T) {
	log := fakePodman(t)
	t.Setenv("CREATED_ID", "private diagnostic")
	called := false
	result, err := New().RunRegistered(testContext(t), spec.RunOptions{ContainerName: "test", Image: "image"}, func(context.Context, string) error { called = true; return nil })
	if err == nil || strings.Contains(err.Error(), "private diagnostic") || !result.CreateUnknown || result.ContainerID != "" || called || calls(t, log) != "create\n" {
		t.Fatalf("result=%+v err=%v calls=%q", result, err, calls(t, log))
	}
}
func TestRegisteredRunRequiresRegistrationBeforeCreate(t *testing.T) {
	log := fakePodman(t)
	_, err := New().RunRegistered(testContext(t), spec.RunOptions{ContainerName: "test", Image: "image"}, nil)
	if err == nil || calls(t, log) != "" {
		t.Fatalf("err=%v calls=%q", err, calls(t, log))
	}
}

func TestRegisteredRunRejectsOversizedCreateOutput(t *testing.T) {
	log := fakePodman(t)
	t.Setenv("CREATED_ID", strings.Repeat("a", 64)+strings.Repeat(" ", 1024))
	called := false
	result, err := New().RunRegistered(testContext(t), spec.RunOptions{ContainerName: "test", Image: "image"}, func(context.Context, string) error { called = true; return nil })
	if err == nil || !result.CreateUnknown || called || calls(t, log) != "create\n" {
		t.Fatalf("result=%+v err=%v calls=%q", result, err, calls(t, log))
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func TestRegisteredRunRequiresDeadlineBeforeCreate(t *testing.T) {
	log := fakePodman(t)
	_, err := New().RunRegistered(context.Background(), spec.RunOptions{ContainerName: "test", Image: "image"}, func(context.Context, string) error { return nil })
	if err == nil || calls(t, log) != "" {
		t.Fatalf("err=%v calls=%q", err, calls(t, log))
	}
}
func TestRegisteredRunCreateCancellationIsUnknown(t *testing.T) {
	log := fakePodman(t)
	t.Setenv("CREATE_WAIT", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	called := false
	result, err := New().RunRegistered(ctx, spec.RunOptions{ContainerName: "test", Image: "image"}, func(context.Context, string) error { called = true; return nil })
	if err == nil || !result.CreateUnknown || called || calls(t, log) != "create\n" {
		t.Fatalf("result=%+v err=%v calls=%q", result, err, calls(t, log))
	}
}
func TestRegisteredRunStartCancellationIsUnknown(t *testing.T) {
	log := fakePodman(t)
	t.Setenv("START_WAIT", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := New().RunRegistered(ctx, spec.RunOptions{ContainerName: "test", Image: "image"}, func(context.Context, string) error { return nil })
	if err == nil || !result.StartUnknown || result.ContainerID != strings.Repeat("a", 64) || calls(t, log) != "create\nstart\n" {
		t.Fatalf("result=%+v err=%v calls=%q", result, err, calls(t, log))
	}
}
func TestRegisteredRunBoundsInheritedPipe(t *testing.T) {
	log := fakePodman(t)
	t.Setenv("HOLD_PIPE", "1")
	started := time.Now()
	result, err := New().RunRegistered(testContext(t), spec.RunOptions{ContainerName: "test", Image: "image"}, func(context.Context, string) error { return nil })
	if err == nil || !result.CreateUnknown || time.Since(started) > time.Second || calls(t, log) != "create\n" {
		t.Fatalf("result=%+v err=%v calls=%q elapsed=%v", result, err, calls(t, log), time.Since(started))
	}
}

func TestRegisteredRunDoesNotStartAfterRegistrationDeadline(t *testing.T) {
	log := fakePodman(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := New().RunRegistered(ctx, spec.RunOptions{ContainerName: "test", Image: "image"}, func(callbackCtx context.Context, id string) error { <-callbackCtx.Done(); return nil })
	if err == nil || result.ContainerID != strings.Repeat("a", 64) || calls(t, log) != "create\n" {
		t.Fatalf("result=%+v err=%v calls=%q", result, err, calls(t, log))
	}
}
