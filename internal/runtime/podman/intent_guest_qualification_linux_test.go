//go:build linux && podman_guest_qualification

package podman

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/fpp-125/metaclaw/internal/policy"
	"github.com/fpp-125/metaclaw/internal/runtime/spec"
)

const guestPrefix = "/opt/metaclaw-qualification"

const guestImage = "sha256:9779a4143ae4607c8702ee40a94ae02c0c7b759c567588b4ef95a07d3208e005"

func verifyGuestPrefix() error {
	opt, err := os.Lstat("/opt")
	if err != nil || !opt.IsDir() || opt.Mode().Perm()&0022 != 0 {
		return errors.New("guest prefix parent invalid")
	}
	optStat, ok := opt.Sys().(*syscall.Stat_t)
	if !ok || optStat.Uid != 0 {
		return errors.New("guest prefix parent owner invalid")
	}
	for _, name := range []string{"", "/usr", "/usr/bin", "/usr/lib", "/usr/lib/podman", "/usr/lib/x86_64-linux-gnu"} {
		info, err := os.Lstat(guestPrefix + name)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0755 {
			return errors.New("guest prefix directory invalid")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || st.Gid != 0 {
			return errors.New("guest prefix owner invalid")
		}
	}
	files := map[string]struct {
		mode os.FileMode
		sha  string
	}{
		"/usr/bin/podman":                             {0755, "6627da0abfd3b0189498089319f5759c7b132bb6a51130bf8ff43d7f102d9673"},
		"/usr/bin/conmon":                             {0755, "856d10b5842ae5dd7f4cf73a60d0f1a764bdcd0cfadc447adb0b0ef41a935412"},
		"/usr/bin/crun":                               {0755, "0e6d2727a3bcb013652543f6c8124a24cdea863ee0a99038c55b3591c0d8c126"},
		"/usr/bin/newuidmap":                          {os.ModeSetuid | 0755, "fd13a73987411f71b8b135cf55ffa00db048754f8d1faf507b6b4aa6204d0ddc"},
		"/usr/bin/newgidmap":                          {os.ModeSetuid | 0755, "745ce9348600b27fa3007f7df7c115d6e586cef163e89caa44cac4e2f9c8d52c"},
		"/usr/lib/podman/netavark":                    {0755, "53fc9fe0ff1d80159713d76ec609984ce38ed390cc1729847aa55f4e6a8e9e2f"},
		"/usr/lib/x86_64-linux-gnu/libsubid.so.5.0.0": {0644, "4973ce6852e811cb632533450e2f2748340d0752f4bc93d63eda8cde1cb60b4a"},
		"/usr/lib/x86_64-linux-gnu/libyajl.so.2.1.0":  {0644, "c54f554ef49cc941d85d56714930d06f39e44bb8968cecb2ee52503c834df04d"},
	}
	for path, expected := range files {
		file, err := os.Open(guestPrefix + path)
		if err != nil {
			return errors.New("guest binary unavailable")
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return errors.New("guest binary stat failed")
		}
		linkInfo, err := os.Lstat(guestPrefix + path)
		if err != nil || !linkInfo.Mode().IsRegular() || !os.SameFile(info, linkInfo) || info.Mode() != expected.mode {
			file.Close()
			return errors.New("guest binary mode invalid")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || st.Gid != 0 {
			file.Close()
			return errors.New("guest binary ownership invalid")
		}
		h := sha256.New()
		_, err = io.Copy(h, file)
		file.Close()
		if err != nil || fmt.Sprintf("%x", h.Sum(nil)) != expected.sha {
			return errors.New("guest binary digest mismatch")
		}
	}
	for path, target := range map[string]string{"/usr/lib/x86_64-linux-gnu/libsubid.so.5": "libsubid.so.5.0.0", "/usr/lib/x86_64-linux-gnu/libyajl.so.2": "libyajl.so.2.1.0"} {
		value, err := os.Readlink(guestPrefix + path)
		if err != nil || value != target {
			return errors.New("guest library symlink invalid")
		}
	}
	return nil
}

func normalizedGuestImageID(value string) (string, bool) {
	value = strings.TrimPrefix(value, "sha256:")
	return value, fullContainerID.MatchString(value)
}

func guestCredentials() error {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return errors.New("credentials unavailable")
	}
	values := map[string][]string{}
	for _, line := range strings.Split(string(status), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if ok {
			values[key] = strings.Fields(rest)
		}
	}
	for _, key := range []string{"Uid", "Gid"} {
		if len(values[key]) != 4 {
			return errors.New("credential fields malformed")
		}
		for _, value := range values[key] {
			if value != "1000" {
				return errors.New("unexpected credentials")
			}
		}
	}
	if len(values["Groups"]) != 1 || values["Groups"][0] != "1000" {
		return errors.New("unexpected groups")
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if len(values[key]) != 1 || values[key][0] != "0000000000000000" {
			return errors.New("unexpected capabilities")
		}
	}
	return nil
}

// Guest-visible checks cannot attest the host's QEMU configuration, network
// attachments or storage isolation. Those require independent host evidence.
func guestPreflight() error {
	if err := verifyGuestPrefix(); err != nil {
		return err
	}
	allow := map[string]bool{"PATH": true, "HOME": true, "XDG_RUNTIME_DIR": true, "XDG_CONFIG_HOME": true, "TMPDIR": true, "CONTAINERS_CONF": true, "CONTAINERS_STORAGE_CONF": true, "QUAL_BASE": true, "QUAL_IMAGE": true, "QUAL_UID": true, "LD_LIBRARY_PATH": true}
	for _, v := range os.Environ() {
		name, _, ok := strings.Cut(v, "=")
		if !ok || !allow[name] {
			return errors.New("unexpected environment")
		}
	}
	if os.Geteuid() != 1000 || os.Getegid() != 1000 || os.Getenv("QUAL_UID") != strconv.Itoa(os.Geteuid()) || os.Getenv("QUAL_IMAGE") != guestImage {
		return errors.New("identity or image invalid")
	}
	if err := guestCredentials(); err != nil {
		return err
	}
	base := os.Getenv("QUAL_BASE")
	if !filepath.IsAbs(base) || filepath.Clean(base) != base {
		return errors.New("private root invalid")
	}
	for _, p := range []string{base, filepath.Join(base, "root"), filepath.Join(base, "runroot"), filepath.Join(base, "tmp"), filepath.Join(base, "home"), filepath.Join(base, "runtime"), filepath.Join(base, "config"), filepath.Join(base, "hooks"), filepath.Join(base, "bin"), filepath.Join(base, "journal")} {
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() || i.Mode().Perm() != 0700 {
			return errors.New("private directory invalid")
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != uint32(os.Geteuid()) {
			return errors.New("private directory owner invalid")
		}
	}
	if os.Getenv("HOME") != filepath.Join(base, "home") || os.Getenv("XDG_RUNTIME_DIR") != filepath.Join(base, "runtime") || os.Getenv("XDG_CONFIG_HOME") != filepath.Join(base, "config") || os.Getenv("TMPDIR") != filepath.Join(base, "tmp") || os.Getenv("PATH") != filepath.Join(base, "bin")+":"+guestPrefix+"/usr/bin:/usr/bin:/bin" || os.Getenv("LD_LIBRARY_PATH") != guestPrefix+"/usr/lib/x86_64-linux-gnu" || os.Getenv("CONTAINERS_CONF") != filepath.Join(base, "config/containers.conf") || os.Getenv("CONTAINERS_STORAGE_CONF") != filepath.Join(base, "config/storage.conf") {
		return errors.New("environment paths invalid")
	}
	for name, expected := range map[string]string{"containers.conf": "[containers]\nvolumes = []\n[engine]\nhooks_dir = []\n", "storage.conf": "[storage]\ndriver = \"vfs\"\n"} {
		path := filepath.Join(base, "config", name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("configuration permissions invalid")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 1000 {
			return errors.New("configuration owner invalid")
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != expected {
			return errors.New("configuration contents invalid")
		}
	}
	hooks, err := os.ReadDir(filepath.Join(base, "hooks"))
	if err != nil || len(hooks) != 0 {
		return errors.New("hooks directory not empty")
	}
	for _, path := range []string{"/etc/containers/mounts.conf", "/usr/share/containers/mounts.conf"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("host mounts configuration present or unknown")
		}
	}
	vendor, e := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if e != nil || strings.TrimSpace(string(vendor)) != "QEMU" {
		return errors.New("QEMU guest not visible")
	}
	interfaces, e := os.ReadDir("/sys/class/net")
	if e != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		return errors.New("guest network interface not loopback-only")
	}
	routes, e := os.ReadFile("/proc/net/route")
	if e != nil {
		return errors.New("IPv4 route table unavailable")
	}
	lines := strings.Split(strings.TrimSpace(string(routes)), "\n")
	if len(lines) < 1 || !strings.HasPrefix(lines[0], "Iface") {
		return errors.New("IPv4 route table malformed")
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return errors.New("IPv4 route malformed")
		}
		flags, e := strconv.ParseUint(fields[3], 16, 32)
		if e != nil {
			return errors.New("IPv4 flags malformed")
		}
		if fields[1] == "00000000" && flags&1 != 0 {
			return errors.New("IPv4 default route exists")
		}
	}
	v6, e := os.ReadFile("/proc/net/ipv6_route")
	if e != nil {
		return errors.New("IPv6 route table unavailable")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(v6)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return errors.New("IPv6 route malformed")
		}
		flags, e := strconv.ParseUint(fields[8], 16, 32)
		if e != nil {
			return errors.New("IPv6 flags malformed")
		}
		if fields[0] == strings.Repeat("0", 32) && fields[1] == "00" && flags&1 != 0 {
			return errors.New("IPv6 default route exists")
		}
	}
	return nil
}
func TestGuestEnvironmentPreflight(t *testing.T) {
	if err := guestPreflight(); err != nil {
		t.Fatal(err)
	}
}

// This intentionally refuses ownership: it does not prove independent custody,
// positive start, crash recovery or live deployment.
func TestGuestIntentRefusesOwner(t *testing.T) {
	if err := guestPreflight(); err != nil {
		t.Fatal(err)
	}
	base := os.Getenv("QUAL_BASE")
	args := []string{"--conmon", guestPrefix + "/usr/bin/conmon", "--runtime", guestPrefix + "/usr/bin/crun", "--root", filepath.Join(base, "root"), "--runroot", filepath.Join(base, "runroot"), "--tmpdir", filepath.Join(base, "tmp"), "--storage-driver", "vfs", "--events-backend", "none", "--hooks-dir", filepath.Join(base, "hooks")}
	run := func(more ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, guestPrefix+"/usr/bin/podman", append(append([]string{}, args...), more...)...).Output()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	binding := IntentBinding{OperationDigest: strings.Repeat("a", 64), RunDigest: strings.Repeat("b", 64), Generation: 1}
	var rec IntentRecord
	result, err := New().RunWithIntent(ctx, spec.RunOptions{Image: guestImage, Policy: policy.Policy{Network: policy.NetworkPolicy{Mode: "none"}}}, filepath.Join(base, "journal"), binding, func(_ context.Context, r IntentRecord) error { rec = r; return errors.New("owner refused") })
	if err == nil || result.CreateUnknown || !fullContainerID.MatchString(result.ContainerID) || rec.ContainerID != result.ContainerID {
		t.Fatal("creation or refusal unconfirmed; retain state")
	}
	raw, err := os.ReadFile(filepath.Join(base, "journal", binding.OperationDigest+".registration.json"))
	if err != nil {
		t.Fatal("registration missing; retain state")
	}
	var disk IntentRecord
	if json.Unmarshal(raw, &disk) != nil || disk != rec {
		t.Fatal("registration mismatch; retain state")
	}
	out, err := run("inspect", result.ContainerID)
	if err != nil {
		t.Fatal("exact ID inspect failed; retain state")
	}
	var rows []struct {
		ID    string `json:"Id"`
		Name  string `json:"Name"`
		Image string `json:"Image"`
		State struct {
			Status  string `json:"Status"`
			Running bool   `json:"Running"`
		} `json:"State"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		Mounts     []json.RawMessage `json:"Mounts"`
		HostConfig struct {
			NetworkMode string `json:"NetworkMode"`
		} `json:"HostConfig"`
	}
	if json.Unmarshal(out, &rows) != nil || len(rows) != 1 {
		t.Fatal("inspect shape invalid; retain state")
	}
	imageID, imageOK := normalizedGuestImageID(rows[0].Image)
	if rows[0].ID != result.ContainerID || strings.TrimPrefix(rows[0].Name, "/") != rec.ContainerName || !imageOK || imageID != strings.TrimPrefix(guestImage, "sha256:") || rows[0].Config.Labels["io.metaclaw.intent"] != rec.Marker || rows[0].State.Running || rows[0].State.Status != "created" || rows[0].HostConfig.NetworkMode != "none" || len(rows[0].Mounts) != 0 {
		t.Fatal("ownership, image or unstarted state not proved; retain state")
	}
	if _, err = run("rm", result.ContainerID); err != nil {
		t.Fatal("exact verified removal failed; retain state")
	}
	if _, err = run("container", "exists", result.ContainerID); err == nil {
		t.Fatal("container remains; retain state")
	} else {
		var e *exec.ExitError
		if !errors.As(err, &e) || e.ExitCode() != 1 {
			t.Fatal("absence unknown; retain state")
		}
	}
}
