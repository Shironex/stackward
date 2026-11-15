package apply_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
)

func TestLockRefusesASecondRunWithTheHoldersID(t *testing.T) {
	root := t.TempDir()
	h, _ := applytest.NewHost(root)
	const first, second = "20260301T120000Z-aaaaaa", "20260301T120001Z-bbbbbb"

	// Two goroutines race for the lock through the host seam; exactly one
	// wins, and the loser is refused with the winner's run id.
	type result struct {
		id      string
		release func() error
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, id := range []string{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rel, err := apply.AcquireRunLock(h, id)
			results <- result{id, rel, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var won, lost result
	for r := range results {
		if r.err == nil {
			won = r
		} else {
			lost = r
		}
	}
	if won.release == nil || lost.err == nil {
		t.Fatalf("want one winner and one refusal, got winner %v and %v", won.id, lost.err)
	}
	var held *apply.HeldError
	if !errors.As(lost.err, &held) || held.Holder != won.id {
		t.Fatalf("the refusal %v does not name the holder %s", lost.err, won.id)
	}
	if !strings.Contains(lost.err.Error(), won.id) || !apply.IsHeld(lost.err) {
		t.Errorf("message %q", lost.err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, apply.RunLockPath)); strings.TrimSpace(string(b)) != won.id {
		t.Errorf("lock file holds %q", b)
	}

	// Released: the loser can go now, and the file names the new holder.
	if err := won.release(); err != nil {
		t.Fatal(err)
	}
	rel, err := apply.AcquireRunLock(h, lost.id)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	if err := rel(); err != nil {
		t.Fatal(err)
	}
}

func TestLockTakesAStaleFile(t *testing.T) {
	root := t.TempDir()
	// A file left by a run that died: content, but no live flock.
	applytest.Write(t, root, apply.RunLockPath, "20250101T000000Z-dead00\n", 0o600)
	h, _ := applytest.NewHost(root)
	rel, err := apply.AcquireRunLock(h, "20260301T120000Z-cccccc")
	if err != nil {
		t.Fatalf("a stale file blocked the lock: %v", err)
	}
	if b, _ := applytest.Read(t, root, apply.RunLockPath); strings.TrimSpace(b) != "20260301T120000Z-cccccc" {
		t.Errorf("lock file holds %q", b)
	}
	if err := rel(); err != nil {
		t.Fatal(err)
	}
	if b, _ := applytest.Read(t, root, apply.RunLockPath); b != "" {
		t.Errorf("a released lock still names %q", b)
	}
}
