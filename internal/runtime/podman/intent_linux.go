package podman

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/fpp-125/metaclaw/internal/runtime/spec"
	"golang.org/x/sys/unix"
)

// IntentBinding contains caller-derived nonsecret digests, not authorization.
type IntentBinding struct {
	OperationDigest string `json:"operation_digest"`
	RunDigest       string `json:"run_digest"`
	Generation      uint64 `json:"generation"`
}

// IntentRecord is evidence only. It proves neither independent ownership nor cleanup.
type IntentRecord struct {
	Schema        string        `json:"schema"`
	Binding       IntentBinding `json:"binding"`
	Marker        string        `json:"marker"`
	ContainerName string        `json:"container_name"`
	ContainerID   string        `json:"container_id,omitempty"`
}

// openJournal rejects symlinks and untrusted writable ancestors. The returned
// directory FD anchors all writes. Same-UID writers remain a trusted boundary.
func openJournal(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid journal path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	check := func(fd int, final bool) error {
		var s unix.Stat_t
		if e := unix.Fstat(fd, &s); e != nil {
			return e
		}
		uid := uint32(os.Geteuid())
		if s.Uid != uid && s.Uid != 0 {
			return errors.New("untrusted directory owner")
		}
		if final {
			if s.Uid != uid || s.Mode&0077 != 0 {
				return errors.New("journal is not private")
			}
		} else if s.Mode&0022 != 0 && !(s.Uid == 0 && s.Mode&unix.S_ISVTX != 0) {
			return errors.New("writable ancestor")
		}
		return nil
	}
	if err = check(fd, path == "/"); err != nil {
		unix.Close(fd)
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, p := range parts {
		if p == "" {
			continue
		}
		next, e := unix.Openat(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
		if err = check(fd, i == len(parts)-1); err != nil {
			unix.Close(fd)
			return nil, err
		}
	}
	return os.NewFile(uintptr(fd), "journal"), nil
}
func sameJournal(path string, d *os.File) bool {
	other, err := openJournal(path)
	if err != nil {
		return false
	}
	defer other.Close()
	a, e := d.Stat()
	if e != nil {
		return false
	}
	b, e := other.Stat()
	return e == nil && os.SameFile(a, b)
}
func createRecord(d *os.File, name string, data []byte) (os.FileInfo, error) {
	fd, err := unix.Openat(int(d.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	var info os.FileInfo
	if err == nil {
		info, err = f.Stat()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err == nil {
		err = d.Sync()
	}
	return info, err
}
func sameClaim(d *os.File, name string, original os.FileInfo) bool {
	fd, e := unix.Openat(int(d.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return false
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, e := f.Stat()
	return e == nil && info.Mode().IsRegular() && os.SameFile(original, info)
}

// RunWithIntent is an opt-in, non-CLI seam. Journal data does not constitute an
// independent owner or recovery. The owner callback must independently establish
// custody. Unknown outcomes and existing claims are never automatically retried.
func (a *Adapter) RunWithIntent(ctx context.Context, opts spec.RunOptions, dir string, binding IntentBinding, ownerAck func(context.Context, IntentRecord) error) (RegisteredResult, error) {
	return a.runWithIntent(ctx, opts, dir, binding, ownerAck, createRecord, nil)
}

func (a *Adapter) runWithIntent(ctx context.Context, opts spec.RunOptions, dir string, binding IntentBinding, ownerAck func(context.Context, IntentRecord) error, persistRegistration func(*os.File, string, []byte) (os.FileInfo, error), onRegistrationDone func()) (RegisteredResult, error) {
	if ownerAck == nil || !fullContainerID.MatchString(binding.OperationDigest) || !fullContainerID.MatchString(binding.RunDigest) || binding.Generation == 0 || opts.ContainerName != "" {
		return RegisteredResult{}, errors.New("invalid intent input")
	}
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return RegisteredResult{}, errors.New("active deadline required")
	}
	if validateRegisteredEnv(opts.Policy, opts.Env) != nil {
		return RegisteredResult{}, errors.New("container environment unavailable")
	}
	d, err := openJournal(dir)
	if err != nil {
		return RegisteredResult{}, errors.New("intent journal unavailable")
	}
	defer d.Close()
	registrationFD, err := unix.FcntlInt(d.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return RegisteredResult{}, errors.New("intent journal unavailable")
	}
	registrationDir := os.NewFile(uintptr(registrationFD), "registration journal")
	transferred := false
	defer func() {
		if !transferred {
			registrationDir.Close()
		}
	}()
	var b [16]byte
	if _, err = rand.Read(b[:]); err != nil {
		return RegisteredResult{}, errors.New("intent marker unavailable")
	}
	marker := hex.EncodeToString(b[:])
	rec := IntentRecord{Schema: "metaclaw.podman-intent.v1", Binding: binding, Marker: marker, ContainerName: "metaclaw-intent-" + marker}
	raw, err := json.Marshal(rec)
	if err != nil {
		return RegisteredResult{}, errors.New("intent encoding failed")
	}
	name := binding.OperationDigest + ".json"
	claim, err := createRecord(d, name, raw)
	if err != nil {
		return RegisteredResult{}, errors.New("intent already claimed or persistence failed")
	}
	if !sameJournal(dir, d) || !sameClaim(d, name, claim) {
		return RegisteredResult{}, errors.New("intent identity changed")
	}
	opts.ContainerName = rec.ContainerName
	result, runErr := a.runRegistered(ctx, opts, marker, func(ctx context.Context, id string) error {
		defer registrationDir.Close()
		if onRegistrationDone != nil {
			defer onRegistrationDone()
		}
		if ctx.Err() != nil {
			return errors.New("registration expired")
		}
		var registration os.FileInfo
		registrationName := binding.OperationDigest + ".registration.json"
		if err := func() error {
			if !sameJournal(dir, registrationDir) || !sameClaim(registrationDir, name, claim) {
				return errors.New("intent identity changed")
			}
			rec.ContainerID = id
			raw, err := json.Marshal(rec)
			if err != nil {
				return errors.New("registration encoding failed")
			}
			registration, err = persistRegistration(registrationDir, registrationName, raw)
			if err != nil {
				return errors.New("registration persistence failed")
			}
			if !sameJournal(dir, registrationDir) || !sameClaim(registrationDir, name, claim) || !sameClaim(registrationDir, registrationName, registration) {
				return errors.New("intent identity changed")
			}
			return nil
		}(); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return errors.New("registration expired")
		}
		if err := ownerAck(ctx, rec); err != nil {
			return err
		}
		if !sameJournal(dir, registrationDir) || !sameClaim(registrationDir, name, claim) || !sameClaim(registrationDir, registrationName, registration) {
			return errors.New("intent identity changed")
		}
		return nil
	})
	// A valid create ID means runRegistered started the callback and transferred
	// this descriptor to it. A failed/unknown create never starts the callback.
	transferred = result.ContainerID != ""
	return result, runErr
}
