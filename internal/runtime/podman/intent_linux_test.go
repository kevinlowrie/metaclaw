package podman

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/fpp-125/metaclaw/internal/runtime/spec"
)

func intentBinding() IntentBinding {
	return IntentBinding{OperationDigest: strings.Repeat("a", 64), RunDigest: strings.Repeat("b", 64), Generation: 1}
}
func privateJournal(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func TestIntentPersistsBeforeCreateAndIDBeforeOwnerAck(t *testing.T) {
	log := fakePodman(t)
	journal := privateJournal(t)
	snapshot, arguments := filepath.Join(t.TempDir(), "snapshot"), filepath.Join(t.TempDir(), "args")
	t.Setenv("JOURNAL", journal)
	t.Setenv("SNAPSHOT", snapshot)
	t.Setenv("ARGUMENTS", arguments)
	var saved IntentRecord
	_, err := New().RunWithIntent(testContext(t), spec.RunOptions{Image: "fixture"}, journal, intentBinding(), func(_ context.Context, got IntentRecord) error {
		raw, e := os.ReadFile(filepath.Join(journal, intentBinding().OperationDigest+".registration.json"))
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(raw, &saved); e != nil {
			t.Fatal(e)
		}
		if got.ContainerID != strings.Repeat("a", 64) || saved.ContainerID != got.ContainerID || saved.Marker != got.Marker || saved.ContainerName != got.ContainerName || calls(t, log) != "create\n" {
			t.Fatalf("wrong persisted identity or order: %+v %+v", got, saved)
		}
		return nil
	})
	if err != nil || calls(t, log) != "create\nstart\n" {
		t.Fatalf("err=%v calls=%q", err, calls(t, log))
	}
	var before IntentRecord
	raw, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &before); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(arguments)
	if err != nil {
		t.Fatal(err)
	}
	if before.ContainerID != "" || before.Marker != saved.Marker || before.ContainerName != saved.ContainerName || !strings.Contains(string(args), "--name\n"+saved.ContainerName+"\n--label\nio.metaclaw.intent="+saved.Marker+"\n") {
		t.Fatalf("create intent mismatch: %+v %q", before, args)
	}
}
func TestIntentUnknownCreateAndConflictNeverRetry(t *testing.T) {
	log := fakePodman(t)
	t.Setenv("CREATE_FAIL", "1")
	journal := privateJournal(t)
	binding := intentBinding()
	result, err := New().RunWithIntent(testContext(t), spec.RunOptions{Image: "fixture"}, journal, binding, func(context.Context, IntentRecord) error { return nil })
	if err == nil || !result.CreateUnknown {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, b := range []IntentBinding{binding, {OperationDigest: binding.OperationDigest, RunDigest: strings.Repeat("c", 64), Generation: 2}} {
		_, err = New().RunWithIntent(testContext(t), spec.RunOptions{Image: "fixture"}, journal, b, func(context.Context, IntentRecord) error { return nil })
		if err == nil {
			t.Fatal("retry allowed")
		}
	}
	if calls(t, log) != "create\n" {
		t.Fatalf("unexpected calls %q", calls(t, log))
	}
}
func TestIntentConcurrentClaimsOnlyOneCreate(t *testing.T) {
	log := fakePodman(t)
	journal := privateJournal(t)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = New().RunWithIntent(testContext(t), spec.RunOptions{Image: "fixture"}, journal, intentBinding(), func(context.Context, IntentRecord) error { return nil })
		}()
	}
	wg.Wait()
	if calls(t, log) != "create\nstart\n" {
		t.Fatalf("unexpected calls %q", calls(t, log))
	}
}
func TestIntentNoOwnerAckMeansNoStart(t *testing.T) {
	log := fakePodman(t)
	_, err := New().RunWithIntent(testContext(t), spec.RunOptions{Image: "fixture"}, t.TempDir(), intentBinding(), nil)
	if err == nil || calls(t, log) != "" {
		t.Fatalf("err=%v calls=%q", err, calls(t, log))
	}
}

func TestIntentOwnerRefusalDoesNotStart(t *testing.T) {
	log := fakePodman(t)
	journal := privateJournal(t)
	result, err := New().RunWithIntent(testContext(t), spec.RunOptions{Image: "fixture"}, journal, intentBinding(), func(context.Context, IntentRecord) error { return errors.New("owner unavailable") })
	if err == nil || result.ContainerID != strings.Repeat("a", 64) || calls(t, log) != "create\n" {
		t.Fatalf("result=%+v err=%v calls=%q", result, err, calls(t, log))
	}
}
func TestIntentRegistrationPersistenceFailureDoesNotAckOrStart(t *testing.T) {
	log := fakePodman(t)
	journal := privateJournal(t)
	t.Setenv("BLOCK_REGISTRATION", filepath.Join(journal, intentBinding().OperationDigest+".registration.json"))
	acked := false
	_, err := New().RunWithIntent(testContext(t), spec.RunOptions{Image: "fixture"}, journal, intentBinding(), func(context.Context, IntentRecord) error { acked = true; return nil })
	if err == nil || acked || calls(t, log) != "create\n" {
		t.Fatalf("err=%v ack=%v calls=%q", err, acked, calls(t, log))
	}
}

func TestIntentRejectsSwappedJournalAndReplacedClaim(t *testing.T) {
	for _, mode := range []string{"SWAP_JOURNAL", "REPLACE_CLAIM"} {
		t.Run(mode, func(t *testing.T) {
			log := fakePodman(t)
			journal := privateJournal(t)
			value := journal
			if mode == "REPLACE_CLAIM" {
				value = filepath.Join(journal, intentBinding().OperationDigest+".json")
			}
			t.Setenv(mode, value)
			ack := false
			_, err := New().RunWithIntent(testContext(t), spec.RunOptions{Image: "fixture"}, journal, intentBinding(), func(context.Context, IntentRecord) error { ack = true; return nil })
			if err == nil || ack || calls(t, log) != "create\n" {
				t.Fatalf("err=%v ack=%v calls=%q", err, ack, calls(t, log))
			}
		})
	}
}
func TestIntentRejectsSymlinkJournal(t *testing.T) {
	log := fakePodman(t)
	actual := privateJournal(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	_, err := New().RunWithIntent(testContext(t), spec.RunOptions{Image: "fixture"}, link, intentBinding(), func(context.Context, IntentRecord) error { return nil })
	if err == nil || calls(t, log) != "" {
		t.Fatalf("err=%v calls=%q", err, calls(t, log))
	}
}
