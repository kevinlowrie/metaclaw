package podman

import (
	"context"
	"errors"
	"io"
	"os"
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
	ContainerID         string
	CreateUnknown       bool
	RegistrationUnknown bool
	StartUnknown        bool
	ExitCode            int
}

// RunRegistered is a preparatory adapter seam, not an ownership service. The
// callback must persist the exact ID and establish an independent owner before
// acknowledging. A callback must honor its context and return promptly. If it
// does not, the call returns at its deadline with registration unknown; the
// callback may still be running, so the independent owner must reconcile it.
// The caller is responsible for crash recovery and cleanup. A create can have host-side effects such as image pulls
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
	envFile, err := registeredEnvFile(opts.Policy, opts.Env)
	if err != nil {
		return RegisteredResult{}, errors.New("container environment unavailable")
	}
	if envFile != nil {
		defer envFile.Close()
	}
	args := []string{"create", "--name", opts.ContainerName}
	if marker != "" {
		args = append(args, "--label", "io.metaclaw.intent="+marker)
	}
	args = append(args, policyFlags(opts.Policy, nil, opts.Workdir, opts.User, opts.CPU, opts.Memory)...)
	if envFile != nil {
		args = append(args, "--env-file", "/proc/self/fd/3")
	}
	args = append(args, opts.Image)
	args = append(args, opts.Command...)
	out, overflow, _, err := registeredCommand(ctx, args, envFile, true)
	if err != nil || overflow || !fullContainerID.MatchString(strings.TrimSpace(out)) {
		return RegisteredResult{CreateUnknown: true}, errors.New("container creation outcome unknown")
	}
	id := strings.TrimSpace(out)
	result := RegisteredResult{ContainerID: id}
	registration := make(chan error, 1)
	go func() { registration <- register(ctx, id) }()
	select {
	case err := <-registration:
		if err == nil && ctx.Err() == nil {
			break
		}
		result.RegistrationUnknown = true
		return result, errors.New("container registration not acknowledged")
	case <-ctx.Done():
		result.RegistrationUnknown = true
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
func registeredCommand(ctx context.Context, args []string, envFile *os.File, capture bool) (string, bool, int, error) {
	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.WaitDelay = 250 * time.Millisecond
	// Task variables are provided through an anonymous env file, not the CLI
	// environment, where they could change Podman's runtime or connection.
	cmd.Env = os.Environ()
	if envFile != nil {
		cmd.ExtraFiles = []*os.File{envFile}
	}
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
