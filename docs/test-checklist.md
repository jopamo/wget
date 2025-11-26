# Wget Fork Usability Testing Checklist

This checklist is tailored specifically for testing the usability and functionality of the wget fork with event-driven architecture.

Use this as a "runbook" for manual testing sessions and as a guide for designing comprehensive Meson tests.

---

## Environment & Setup

* [ ] Confirm `build/` is up to date: `ninja -C build`
* [ ] Confirm self binary runs: `./build/src/wget --version`
* [ ] Confirm system `wget` is *not* what you're testing (avoid PATH confusion)
* [ ] Confirm BusyBox is available: `busybox httpd --help`
* [ ] Confirm base Meson tests pass: `meson test -C build`

---

## CLI Help & Discoverability

* [ ] `./build/src/wget --help` prints cleanly in 80-column terminals (no ugly wraps)
* [ ] Options layout is consistent (sections, indent, alignment similar to GNU wget)
* [ ] Unknown options error is clear: `./build/src/wget --no-such-option`
  * [ ] Exit code is non-zero
  * [ ] Error message points at `--help`
* [ ] `--version` output clearly distinguishes your fork (name, version, fork note)

---

## Basic "Happy Path" Downloads

Using your BusyBox httpd test root (or similar):

* [ ] Single small file:
  * [ ] `./build/src/wget http://127.0.0.1:PORT/hello.txt`
  * [ ] File exists and matches source
  * [ ] Exit code is 0
* [ ] Explicit output file: `-O out.txt` works, even when filename has no extension
* [ ] Existing file + `--no-clobber` leaves original untouched and exits sensibly
* [ ] Existing file + `--continue` resumes correctly (no truncation or duplication)

---

## Progress UI & Non-interactive Modes

* [ ] Default progress (`--progress=bar` or default) behaves well:
  * [ ] In a normal terminal (TTY) you get a bar that updates on one line
  * [ ] No garbage characters after completion
* [ ] Non-TTY behavior (redirected stderr or log file):
  * [ ] `./build/src/wget ... 2>stderr.log` produces readable progress/log output
  * [ ] Progress output doesn't spam thousands of lines needlessly
* [ ] `--progress=dot` works and is legible:
  * [ ] For short downloads (a few KB)
  * [ ] For larger ones (hundreds of KB / MB)
* [ ] Switching implementations does not hang:
  * [ ] `--progress=bar` on a TTY completes normally
  * [ ] `--progress=bar` with `stderr` redirected still completes (no deadlock)
  * [ ] `--progress=dot:mega` and other styles work and do not crash
* [ ] `--show-progress` behaves as expected in quiet/less-verbose modes

---

## Error Messages & Failure Handling

* [ ] DNS failure is clear:
  * [ ] `./build/src/wget http://no-such-host.invalid`
  * [ ] Exit code is non-zero
  * [ ] Message clearly indicates DNS failure and which host
* [ ] Connection refused:
  * [ ] Stop BusyBox httpd and run against `127.0.0.1:PORT`
  * [ ] Error states "connection refused" or similar, not generic "network error"
* [ ] HTTP 404:
  * [ ] `./build/src/wget http://127.0.0.1:PORT/missing.txt`
  * [ ] Exit code reflects failure
  * [ ] Message includes HTTP status
* [ ] Timeout behavior:
  * [ ] With a long `/cgi` endpoint or using firewall rules, confirm:
    * [ ] DNS timeout message (with `--dns-timeout=...`)
    * [ ] Connect timeout message (with `--connect-timeout=...`)
    * [ ] Read timeout message (with `--read-timeout=...`)
  * [ ] Messages indicate which phase timed out

---

## Configuration & `--no-config`

* [ ] With a `.wgetrc` present, normal `wget` respects options you expect
* [ ] With `--no-config`, configuration is ignored:
  * [ ] No unexpected headers/proxy
  * [ ] No unexpected output directory
* [ ] Error messages for malformed config files are understandable

---

## Logging & Output Files

* [ ] `-o logfile` writes all status to `logfile` and keeps stdout clean:
  * [ ] No stray progress bar artifacts in logs
* [ ] `-a logfile` appends cleanly:
  * [ ] No interleaved partial lines from progress UI
* [ ] `--rejected-log=FILE` (if used in your fork) is readable and structured

---

## URL & Path Usability

* [ ] Quoted URLs behave:
  * [ ] Spaces in query/path
  * [ ] `?` and `&` heavy URLs
* [ ] Relative vs absolute links in your recursive mode (if you test recursing later):
  * [ ] Local directory structure is intuitive under `-r` and `-P`

---

## Integration With Scripts & Automation

* [ ] Exit codes are stable and predictable:
  * [ ] 0 for success
  * [ ] Non-zero for DNS/connect/HTTP errors
* [ ] Quiet mode:
  * [ ] `-q` really is quiet enough for cron/logging usage
* [ ] Machine-readable hints:
  * [ ] At least one mode that prints minimal/no progress for parsing
* [ ] Behavior when stdout is a pipe:
  * [ ] `./build/src/wget -O - URL | cat`
  * [ ] No binary/progress junk on stderr that breaks simple pipelines

---

## HTTPS / TLS Usability (if enabled in your build)

* [ ] Self-signed cert with `--no-check-certificate` works without confusing messages
* [ ] Clear error for certificate failure without `--no-check-certificate`
* [ ] `--https-only` behavior:
  * [ ] Mixed HTTP/HTTPS links don't silently downgrade

---

## WARC / Archival Usability (if you keep WARC)

* [ ] `--warc-file` produces files alongside downloads as expected
* [ ] User-facing errors when WARC file cannot be written (disk full, permissions) are clear

---

## Meson Test Harness Usability

Given your current tree (`tests/http/basic` etc):

* [ ] `meson test -C build` is fast enough to run frequently (sub-second or low seconds)
* [ ] `testlog.txt` is readable:
  * [ ] On failure, stderr from `httpd-wrapper.sh` and wget is visible
* [ ] Tests don't leave junk:
  * [ ] No leftover temp dirs under `/tmp`
  * [ ] No lingering `httpd` processes if tests are interrupted (Ctrl-C)

---

## Documentation & Discoverability Inside Repo

* [ ] `docs/overview.md`, `event-loop.md`, `http-transaction.md`, etc are reachable from `README` / main doc entry
* [ ] `HACKING.md` explains how to:
  * [ ] Build
  * [ ] Run Meson tests
  * [ ] Add new tests using BusyBox `httpd`
* [ ] CLI docs (`--help`, `docs/cli-integration.md`) mention:
  * [ ] Non-blocking/event-driven design in one or two sentences
  * [ ] Any important differences vs vanilla GNU wget

---

## Usage Notes

- **For manual testing**: Run through sections systematically, checking boxes as you verify functionality
- **For automated testing**: Use this as a guide for what scenarios to implement in Meson tests
- **Event-driven specific**: Pay special attention to non-blocking behavior, timeout handling, and concurrent operations
- **Integration focus**: Test how wget behaves in real-world scenarios like scripts, cron jobs, and pipelines