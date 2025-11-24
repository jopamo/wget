# Repository Guidelines

## Project Structure & Module Organization
This tree is the trimmed downloader core. All implementation and headers live under `src/`, grouped roughly by protocol (`http.c`, `warc.c`), storage helpers (`cookies.c`, `hsts.c`, `xattr.c`), and utility layers (`utils.c`, `xalloc.c`, `progress.c`). Top-level `meson.build` and `meson_options.txt` describe the build graph and feature toggles, while `src/meson.build` lists concrete sources. Policy docs are at the root (`SECURITY.md`, `checklist.md`, `COPYING`, and this file). There are no `lib/`, `gnulib`, or autotools artifacts in this snapshot—keep it that way and avoid committing Meson build directories.

The HTTP client is in the middle of being split into smaller, testable modules. As of now:

* `src/http_request.c` + `src/http_request.h` own request construction (method, headers, serialization).
* `src/http_auth.c` + `src/http_auth.h` own all authentication helpers (basic/digest/NTLM glue, cached host tracking, authorization header generation).
* `src/http_body.c` + `src/http_body.h` handle response body streaming and WARC capture.

`src/http.c` still orchestrates scheduling, connection reuse, and response parsing, but new work should prefer adding focused helpers next to the peers above. The next steps in this refactor are extracting response parsing/stat tracking (future `src/http_response.c`) and retry/state machine helpers, so keep upcoming changes framed around that trajectory instead of adding more ad-hoc helpers to `http.c`.

## Architecture & Event Loop Requirements
`checklist.md` is the authoritative contract: libev and c-ares are mandatory, sockets/DNS/timers must be nonblocking, and the architecture must scale to thousands of concurrent transfers with minimal CPU. Every new subsystem (HTTP client, recursion, cookie persistence, redirect logic) needs to expose libev watchers plus async-safe callbacks, and blocking helpers like `sleep`, synchronous DNS, or buffered stdio calls belong only on worker threads. When in doubt, re-read the “Performance / Parallelism”, “Modern HTTP/TLS”, and “Transition / Cleanup” sections of the checklist and document which boxes your change advances.

See `docs/blocking-helpers.md` for the current list of legacy synchronous helpers that still need to be removed during the refactor; treat anything tagged `LEGACY_BLOCKING` as tech debt.

## Build, Test, and Development Commands
Meson is the only supported build system here. Create a build dir with `meson setup build -Denable_debug_logging=true -Denable_xattr=true` (adjust options from `meson_options.txt` as needed), rebuild via `meson compile -C build`, and install or run with `meson install -C build` or `./build/wget --version`. `meson test -C build` currently has no suites wired up, so lean on targeted manual runs (`./build/wget https://example.org`) before proposing patches. When you add options, wire them through Meson rather than reintroducing configure scripts. Remember that checklist hard requirements (c-ares, libev, optional TLS backends, worker pools) must be detectable/configurable from Meson, so extend `meson_options.txt` and `config.h` when new capabilities require toggles.

## Coding Style & Naming Conventions
Follow the existing GNU-style conventions in `src/`: two-space indentation, K&R braces, lowercase_with_underscores for identifiers, and `_()` wrapping for translatable strings. Keep functionality in cohesive modules (e.g., new protocol helpers belong next to their peers) and update the appropriate header so symbols remain visible. New configuration defines must be plumbed through `meson.build` and `config.h` via `configuration_data()`.

## Testing Guidelines
The legacy Perl/Python harnesses are absent here, so craft smaller focused checks: run the binary against local HTTPS endpoints, exercise FTP/HTTP retry paths, and verify cookie/HSTS persistence. Use `ASAN_OPTIONS=... meson compile -C build` or wrap executions in `valgrind ./build/wget …` when touching network-facing code. Capture the exact CLI you used and note whether optional features (OPIE, xattrs, debug logging) were enabled so reviewers can repeat the scenario. Tests should also demonstrate libev/c-ares integration: highlight how you validated event-loop driven DNS, timer-based retries, per-host concurrency caps, and other “Performance / Parallelism” boxes from the checklist. Keep `checklist.md` updated whenever you land new async behaviors or retire legacy blocking code.

## Commit & Pull Request Guidelines
Commits keep the short, component-tagged form (`src/url.c: tighten verbose logging`) and should explain both the bug/need and the fix. Reference issues with `Fixes: #NNN` when relevant, list any Meson options or pkg-config hints required to reproduce the build, and provide the commands/logs that demonstrate the failure and the fix. Prefer textual logs over screenshots so they are searchable.

## Security & Configuration Tips
OpenSSL and zlib are mandatory dependencies; optional ones (`libpsl`, `libproxy`, `libcares`, `libidn2`, etc.) are auto-detected by Meson. Document any environment adjustments such as ``PKG_CONFIG_PATH=/opt/openssl/lib/pkgconfig`` in your change description, and call out when you disable features (e.g., `-Denable_xattr=false`). c-ares and libev are non-negotiable—do not add synchronous fallbacks. When touching TLS, DNS, cookies, or file persistence, run checks under Valgrind/ASan and mention the results to keep the focus on logic rather than memory hygiene, and spell out any additional hardening that advances the “Modern HTTP/TLS” or “Robustness / Safety” checklist sections.

## Concurrency & Shared State
The downloader still relies on shared process-wide state (cookies, HSTS, DNS caches, OCSP metadata, progress meters). Ensure new code respects existing locking in `threading.c`, keep logging thread-safe, and document any additional state you introduce so reviewers can reason about concurrent runs. When possible, avoid locks entirely on the hot path by leaning on libev primitives (`ev_async`, timers, connection state watchers) as mandated in the checklist.

See `checklist.md` for the full requirements checklist that a modern wget must satisfy.
