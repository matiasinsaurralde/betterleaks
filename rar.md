# RAR crash is **not** fixed by the lzip patch — analysis

**TL;DR** — Commit [`ca147d7`](https://github.com/betterleaks/betterleaks/commit/ca147d725b34268d7b897c6a2058babed4ff7aee)
adds a `recover()` **only** to `decompressorFragments`. That closes the **lzip**
crash (a *decompressor*), but the **RAR** crash travels the *extractor* path
(`extractorFragments`), which the commit never touches. A 16‑byte `.rar` still
terminates the whole `betterleaks` process (exit 2). This document details both
findings, the fix, and why the RAR case survives it.

---

## 1. Background: why a malformed archive can crash the scanner

Betterleaks is meant to be pointed at **untrusted content** (`dir`, `git`,
`github`, `gitlab`, `s3`, `huggingface`, `stdin`). Two structural properties turn
a malformed archive into a process kill:

1. **Archives are identified by file *extension*.** For any non‑`.tar` file,
   `sources/file.go:101` calls `archives.Identify(ctx, s.Path, nil)` with a **nil
   stream**, so `mholt/archives` picks the handler purely from the file name. The
   attacker controls both the extension and the bytes, and the bytes are then fed
   straight into the matching decompression/extraction library.

2. **Nothing on the scan path calls `recover()`** (before `ca147d7` there was not
   a single `recover(` in the tree). Scanning runs inside `fatih/semgroup` worker
   goroutines (`sources/files.go`, `sources/git.go`), so any panic while parsing
   attacker bytes unwinds to the top of a goroutine and kills the process with
   exit code 2.

The dispatch that decides which handler runs lives in `File.Fragments`
(`sources/file.go:127-134`):

```go
if extractor, ok := format.(archives.Extractor); ok {   // checked FIRST
    s.extractorFragments(ctx, extractor, stream, yield)  // RAR, 7z, zip, tar
    return nil
}
if decompressor, ok := format.(archives.Decompressor); ok {
    s.decompressorFragments(ctx, decompressor, stream, yield) // lzip, gz, xz, bz2, ...
    return nil
}
```

Because `Extractor` is checked **first**, and `archives.Rar` implements
`Extractor`, RAR files are **always** handled by `extractorFragments` and never
reach `decompressorFragments`. This ordering is the crux of why the fix misses
RAR.

---

## 2. Finding #1 — `lzip` negative slice bound (6‑byte `.lz`)

**Root cause:** `github.com/sorairolake/lzip-go@v0.3.8`, `reader.go:66`

```go
// lzip-go NewReader()
rb, err := io.ReadAll(r)          // rb = everything after the 6-byte lzip header
...
var lzmaHeader [lzma.HeaderLen]byte
lzmaHeader[0] = lzma.Properties{LC: 3, LP: 0, PB: 2}.Code()
binary.LittleEndian.PutUint32(lzmaHeader[1:5], dictSize)
copy(lzmaHeader[5:], rb[len(rb)-16:len(rb)-8])   // <-- no check that len(rb) >= 16
```

If the post‑header body is shorter than 16 bytes, `len(rb)-16` is negative and the
slice expression panics. The preceding header validation (magic `LZIP`, version,
dictionary‑size byte) is satisfied by a 6‑byte file, so a file that is *only* a
header reaches line 66 with `len(rb) == 0`.

**Handler path (decompressor):**
`ext ".lz"` → `archives.Identify` → `Lzip` (`Decompressor`) →
`sources/file.go:132 decompressorFragments` →
`mholt/archives Lzip.OpenReader` (`lzip.go:46`) →
`lzip-go.NewReader` (`reader.go:66`) → **panic**.

**Trigger (6 bytes):**
```
4c 5a 49 50 01 17            # "LZIP" + version 0x01 + dict-size byte 0x17
```

**Crash:**
```
panic: runtime error: slice bounds out of range [:-8]
github.com/sorairolake/lzip-go.NewReader(...)          reader.go:66
github.com/mholt/archives.Lzip.OpenReader(...)         lzip.go:46
.../sources.(*File).decompressorFragments(...)         sources/file.go:208
.../sources.(*File).Fragments(...)                     sources/file.go:132
exit status 2
```

---

## 3. The lzip fix (`ca147d7`) and what it actually covers

The commit changes exactly one production function, `decompressorFragments`, and
adds a test file. The relevant addition:

```go
func (s *File) decompressorFragments(ctx context.Context, decompressor archives.Decompressor, reader io.Reader, yield FragmentsFunc) {
    var innerReader io.ReadCloser
    defer func() {
        if innerReader != nil {
            _ = innerReader.Close()
        }
        if r := recover(); r != nil {                       // <-- NEW
            logging.Warn().
                Str("path", s.FullPath()).
                Str("panic", fmt.Sprint(r)).
                Msg("skipping compressed file: panic during decompression")
        }
    }()

    innerReader, err := decompressor.OpenReader(reader)
    ...
}
```

* It wraps **`OpenReader` + the subsequent read** of a *decompressor* in a
  `recover()`, converting a panic into a warning + skip.
* Files that flow through `decompressorFragments` are the single‑stream
  **decompressors**: `lzip`, `gz`, `bz2`, `xz`, `zstd`, `lz4`, `brotli`, `snappy`,
  `minlz`, `zlib`.
* **lzip is one of these**, so Finding #1 is genuinely fixed.

`extractorFragments` and the format dispatch in `Fragments` are **unchanged**
(the commit itself notes no other production edits), and `go.mod` dependency
versions are not bumped. So the fix is a *targeted* patch of the decompressor
path, not a class fix.

---

## 4. Finding #2 — `rar` undersized‑buffer slice (16‑byte `.rar`)

**Root cause:** `github.com/nwaples/rardecode/v2@v2.2.2`, `archive50.go:499-503`
(`readBlockHeader`)

```go
crc := b.uint32()                       // consumes 4 of the 7 header bytes
size := int(b.uvarint())                // attacker-controlled "header size" varint
buf := make([]byte, 3+size-len(b))      // <-- can be < 3 when size is small
copy(buf, sizeBuf[4:])
_, err = io.ReadFull(r, buf[3:])        // <-- buf[3:] panics when len(buf) < 3
```

There is no check that `size` is large enough for `len(buf) >= 3`. A RAR5 file
whose block header encodes `size == 0` produces `buf` of length `1`, and `buf[3:]`
panics with `slice bounds out of range [3:1]`.

**Handler path (extractor):**
`ext ".rar"` → `archives.Identify` → `Rar` (`Extractor`) →
`sources/file.go:128 extractorFragments` →
`sources/file.go:169 extractor.Extract` →
`mholt/archives Rar.Extract` (`rar.go:109`) →
`rardecode/v2.NewReader` → `newVolume` → `readerVolume.init` →
`archive50.init` → `mustReadBlockHeader` (`archive50.go:547`) → **panic**.

**Trigger (16 bytes):**
```
52 61 72 21 1a 07 01 00      # RAR5 signature "Rar!\x1a\x07\x01\x00"
00 00 00 00 00 00 00 00      # 8 zero bytes -> block header parses size = 0
```

**Crash:**
```
panic: runtime error: slice bounds out of range [3:1]
github.com/nwaples/rardecode/v2.(*archive50).mustReadBlockHeader(...)  archive50.go:547
github.com/nwaples/rardecode/v2.(*archive50).init(...)                 archive50.go:560
github.com/mholt/archives.Rar.Extract(...)                            rar.go:109
.../sources.(*File).extractorFragments(...)                           sources/file.go:169
.../sources.(*File).Fragments(...)                                    sources/file.go:128
exit status 2
```

Note the stack terminates at **`extractorFragments`**, i.e. the path the fix did
not modify.

---

## 5. Why the fix does **not** cover RAR (empirical proof)

The upstream patch was applied verbatim to `decompressorFragments`, the binary was
rebuilt, and both payloads were re‑scanned with default flags:

```
#1 lzip (.lz)  WITH fix:
   WRN skipping compressed file: panic during decompression
       panic="runtime error: slice bounds out of range [:-8]" path=.../evil.lz
   INF no leaks found
   exit=0                         ✅ panic recovered, scan continues

#2 rar  (.rar) WITH fix:
   panic: runtime error: slice bounds out of range [3:1]
   exit=2                         ❌ process still crashes
```

The lzip panic is caught (`decompressorFragments`); the RAR panic is not, because
it is raised inside `extractorFragments`, which has no `recover()`. The result is
identical to the pre‑fix behavior for RAR.

### Impact (unchanged for RAR)
* **Denial of service** on every scan mode — a few‑byte `.rar` kills the process.
* **Fail‑open secret‑scanning bypass** — demonstrated: a directory containing a
  real, detectable token reports `leaks found: 1`; adding a 16‑byte `payload.rar`
  turns the run into `panic … exit status 2` with the secret **never reported**.
  In `git` mode the payload's NUL bytes make git mark it binary, so it is routed
  through the same archive path — a malicious repo/PR/URL crashes the scan.

---

## 6. Recommended complete fix

The decompressor‑only `recover()` is a point fix. The extractor path (`rar`, and
also `7z`, `zip`, `tar`) currently runs with **no** panic containment. Two
complementary changes:

1. **Contain panics on the extractor path as well.** Add the same `recover()`
   guard to `extractorFragments` (or, cleaner, place a single guard at the
   dispatch site in `Fragments` around both handler calls). Because
   `extractorFragments` recurses into nested entries via `file.Fragments`
   (`sources/file.go:198`), a `recover()` *inside* `extractorFragments` is
   preferable — it protects every nesting level, so a malicious entry inside an
   otherwise‑valid archive can't crash the run either.

   Illustrative:
   ```go
   func (s *File) extractorFragments(ctx context.Context, extractor archives.Extractor, reader io.Reader, yield FragmentsFunc) {
       defer func() {
           if r := recover(); r != nil {
               logging.Warn().
                   Str("path", s.FullPath()).
                   Str("panic", fmt.Sprint(r)).
                   Msg("skipping archive: panic during extraction")
           }
       }()
       ...
   }
   ```

2. **Defense in depth upstream.** Patch `nwaples/rardecode/v2`
   (`archive50.go:501-503`) to validate the header size before slicing — reject
   the block unless `len(buf) >= 3` (equivalently `3 + size >= len(b) + 3`, i.e.
   `size >= len(b)` after the varints are consumed) — instead of indexing
   `buf[3:]` unconditionally.

Also worth doing: identify archive formats by **content signature**, not by
attacker‑controlled extension (`archives.Identify` with the real stream), so a
mis‑named file can't be steered into a fragile handler.

---

## 7. Reproducers

Minimal, self‑contained Go tests (assert the panics reproduce, so they pass while
the upstream libraries are vulnerable):

* `sources/archive_crash_repro_test.go` — `TestLzipTinyFilePanics`,
  `TestRarTinyFilePanics`

```sh
go test ./sources/ -run 'TestLzipTinyFilePanics|TestRarTinyFilePanics' -v
```

Whole‑process crash (default flags):

```sh
mkdir victim
printf 'Rar!\x1a\x07\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00' > victim/evil.rar   # Finding #2 (survives ca147d7)
# or, on an unpatched build:
printf 'LZIP\x01\x17' > victim/evil.lz                                            # Finding #1 (fixed by ca147d7)
betterleaks dir victim        # panics, exit status 2
```
