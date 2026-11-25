package podman

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/fpp-125/metaclaw/internal/runtime/spec"
)

var fullContainerID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// RegisteredResult describes only what this adapter observed. Unknown outcomes
// require reconciliation by the caller's independent owner before any retry.
type RegisteredResult struct {
	ContainerID   string
	CreateUnknown bool
	StartUnknown  bool
	ExitCode      int
}

// RunRegistered is a preparatory adapter seam, not an ownership service. The
// callback must persist the exact ID and establish an independent owner before
// acknowledging. The callback must honor its context and return promptly; a
// blocked callback is not interrupted here. The caller is responsible for crash
// recovery and cleanup. A create can have host-side effects such as image pulls
// and hooks, even before the container is started.
// Errors and command output are intentionally not returned: either can contain
// sensitive container data.
func (a *Adapter) RunRegistered(ctx context.Context, opts spec.RunOptions, register func(context.Context, string) error) (RegisteredResult, error) {
	return a.runRegistered(ctx, opts, "", register)
}

func (a *Adapter) runRegistered(ctx context.Context, opts spec.RunOptions, marker string, register func(context.Context, string) error) (RegisteredResult, error) {
	if register == nil || opts.ContainerName == "" {
		return RegisteredResult{}, errors.New("registration callback and container name required")
	}
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return RegisteredResult{}, errors.New("active deadline required")
	}
	args := []string{"create", "--name", opts.ContainerName}
	if marker != "" {
		args = append(args, "--label", "io.metaclaw.intent="+marker)
	}
	args = append(args, policyFlags(opts.Policy, opts.Env, opts.Workdir, opts.User, opts.CPU, opts.Memory)...)
	args = append(args, opts.Image)
	args = append(args, opts.Command...)
	out, overflow, _, err := registeredCommand(ctx, args, opts.Env, true)
	if err != nil || overflow || !fullContainerID.MatchString(strings.TrimSpace(out)) {
		return RegisteredResult{CreateUnknown: true}, errors.New("container creation outcome unknown")
	}
	id := strings.TrimSpace(out)
	result := RegisteredResult{ContainerID: id}
	if register(ctx, id) != nil || ctx.Err() != nil {
		return result, errors.New("container registration not acknowledged")
	}
	args = []string{"start"}
	if !opts.Detach {
		args = append(args, "--attach")
	}
	args = append(args, id)
	_, _, code, err := registeredCommand(ctx, args, nil, false)
	result.ExitCode = code
	if err != nil {
		result.StartUnknown = true
		return result, errors.New("container start or execution outcome unknown")
	}
	return result, nil
}

// limitedOutput retains only the small creation response while always draining
// the pipe. Unexpectedly large output makes the identity untrustworthy.
type limitedOutput struct {
	data     []byte
	overflow bool
}

func (w *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 128 - len(w.data)
	if remaining < n {
		w.overflow = true
	}
	if remaining > 0 {
		if n < remaining {
			remaining = n
		}
		w.data = append(w.data, p[:remaining]...)
	}
	return n, nil
}
func registeredCommand(ctx context.Context, args []string, env map[string]string, capture bool) (string, bool, int, error) {
	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.Env = mergeEnv(env)
	output := &limitedOutput{}
	if capture {
		cmd.Stdout = output
	} else {
		cmd.Stdout = io.Discard
	}
	cmd.Stderr = io.Discard
	err := cmd.Run()
	code := 0
	if err != nil {
		code = -1
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		}
	}
	return string(output.data), output.overflow, code, err
}
