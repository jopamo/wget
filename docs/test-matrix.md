# Manual test matrix

These scenarios document the repeatable manual checks referenced in section 7 of `checklist.md`. Each entry calls out the checklist coverage, commands to run, what to log, and the success criteria so reviewers can replay the same steps on their machines.

## Environment preparation

1. Start from a clean working tree and create `logs/` for captured output:  
   `mkdir -p logs`
2. Configure + build with debugging enabled so the libev/c-ares traces appear in the logs (adjust options as needed):  
   ```sh
   meson setup build -Denable_debug_logging=true -Denable_xattr=true
   meson compile -C build
   meson configure build   # confirms libev/c-ares/openssl/zlib are enabled
   ```
3. Unless a test states otherwise, run binaries as `./build/src/wget` and pipe stdout/stderr through `tee` so logs are stored under `logs/`.

## Test scenarios

### T0 — Build + dependency verification

*Checklist coverage*: Section 7 bullet 1 (documenting the manual matrix) plus “Hard requirements” dependency verification.  
*Commands*:
```sh
meson setup build -Ddefault_library=static -Denable_debug_logging=true -Denable_xattr=true
meson compile -C build
meson configure build | rg -i 'libev|ares|openssl|zlib'
```
*Log target*: `logs/t0-build.txt`.  
*Expected outcome*: `meson configure` lists `libev`, `c-ares`, `openssl`, and `zlib` in the “Enabled features” section. Build finishes without errors.

### T1 — Baseline HTTP transfer exercising the libev loop

*Checklist coverage*: Section 1 (event loop) + Section 7 bullet 1 documenting the commands.  
*Commands*:
```sh
./build/src/wget -d http://example.org/ \
  -O /tmp/manual-http.html \
  2>&1 | tee logs/t1-http-baseline.log
```
*Expected outcome*: Download completes with `200 OK`, debug output shows `libev` read/write watchers and `c-ares` DNS resolution lines, `/tmp/manual-http.html` contains the page contents, and the log contains no `BLOCKING` warnings.

### T2 — HTTPS/TLS session reuse

*Checklist coverage*: Section 2 (HTTP/TLS performance) + Section 7 documentation requirement.  
*Commands*:
```sh
for i in 1 2; do
  ./build/src/wget -d --secure-protocol=auto https://www.example.org/ \
    -O /tmp/manual-https-$i.html \
    2>&1 | tee logs/t2-https-$i.log
done
```
*Expected outcome*: Both runs succeed. The second log shows “session reused” (OpenSSL) or similar debug text proving TLS session caching. No blocking sleeps appear.

### T3 — Recursive crawl with libev-driven scheduling

*Checklist coverage*: Section 1 (parallel downloads) and Section 3 roadmap steps about recursion driving work via events.  
*Commands*:
```sh
./build/src/wget -d --recursive --level=2 \
  --no-host-directories --directory-prefix=/tmp/manual-rec \
  --execute robots=off \
  https://example.org/ \
  2>&1 | tee logs/t3-recursion.log
```
*Expected outcome*: Scheduler enqueues multiple URLs (traceable via debug logs). `logs/t3-recursion.log` shows interleaved fetch progress without `wget_ev_loop_run_transfers` references. `/tmp/manual-rec/` contains the mirrored tree.

### T4 — Local concurrency stress (50 files, per-host caps)

*Checklist coverage*: Section 1 bullet “Parallel downloading of multiple files” and Section 7 bullet 1 (documented commands/logs).  
*Setup*:
```sh
tmpdir=$(mktemp -d)
pushd "$tmpdir"
for i in $(seq 1 50); do dd if=/dev/urandom of=file-$i.bin bs=4k count=4; done
python3 -m http.server 9000 &
server_pid=$!
popd
```
*Commands*:
```sh
seq 1 50 | sed "s|^|http://127.0.0.1:9000/file-|; s|$|.bin|" > /tmp/manual-urls.txt
./build/src/wget -d --input-file=/tmp/manual-urls.txt \
  --wait=0 --tries=1 --timeout=15 \
  2>&1 | tee logs/t4-concurrency.log
kill $server_pid
```
*Expected outcome*: Log shows multiple concurrent transfers and scheduler host-limit messages. All 50 files land in the current directory. No blocking sleeps or stalls appear even while the local server throttles connections.

### T5 — DNS failure / timeout handling (c-ares)

*Checklist coverage*: Section 1 hard requirements (async DNS) + Section 7 doc requirement.  
*Commands*:
```sh
./build/src/wget -d http://doesnotexist.ares.invalid/ \
  --dns-timeout=2 --tries=1 \
  2>&1 | tee logs/t5-dns.log
```
*Expected outcome*: Debug log shows c-ares watcher/timer activity and an eventual NXDOMAIN/timeout message without blocking the loop. Command exits non-zero while the process remains responsive.

### T6 — ASAN or Valgrind smoke for worker threads

*Checklist coverage*: Section 7 bullet “Automate ASan/Valgrind smoke runs” (manual precursor).  
*Commands*:
```sh
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
meson compile -C build
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
  ./build/src/wget -d https://example.org/ \
  -O /tmp/manual-asan.html \
  2>&1 | tee logs/t6-asan.log
```
*Expected outcome*: Transfer succeeds with no ASAN reports. If Valgrind is preferred, substitute `valgrind ./build/src/wget ...` and capture `logs/t6-valgrind.log`.

---

Record the date, git commit, and local configuration in each log header (e.g., by prepending `git rev-parse HEAD >> logs/tN.log`). When filing patches, mention which test IDs you executed along with the log filenames so reviewers can diff behavior and confirm checklist coverage.
