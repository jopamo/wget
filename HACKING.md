# Agent Guide: Event-Driven Web Downloader Implementation

This guide is for **agents working on the asynchronous web downloader**.  
It explains the **repo layout**, **what you may modify**, and **core rules** for a non-blocking, event-driven codebase.

---

## 0. Agent Contract

If you are an automated agent operating on this repo:

**Do not**

- Introduce blocking I/O (DNS, connect, read, write, sleep, alarm)
- Change the build system (Meson is mandatory)
- Add heavy new dependencies without explicit instructions
- Modify legal headers, license text, or `COPYING`
- Edit generated files or anything under `build/`

**Do**

- Preserve the architecture: **libev + c-ares + non-blocking sockets**
- Keep changes small and testable
- Update docs and tests when behavior changes
- Run relevant tests before and after changes

If you are unsure whether a change is safe, do not make it.

---

## 1. Quick Start for Agents

1. **Check status**  
   Read [`TODO.md`](TODO.md) for:
   - Current phase of the async refactor  
   - Modules in progress  
   - Blocked or reserved tasks  

2. **Understand the architecture**  
   - Read [`docs/overview.md`](docs/overview.md)  
   - Skim [`docs/design-principles.md`](docs/design-principles.md)

3. **Verify build and tests** (from repo root)
   ```bash
   meson setup build   # if not already configured
   meson compile -C build
   meson test -C build
````

Only start modifying code after these steps succeed.

---

## 2. Repository Layout (for Agents)

Paths are relative to the repo root.

### `meson.build`

Top-level build description.

* You may:

  * Add source files or tests when introducing new modules
* You must not:

  * Change project type or language
  * Remove existing targets without explicit instructions

### `src/`

Main C implementation of the async web downloader.

Key modules include:

* `evloop.*` – libev abstraction
* `dns_cares.*` – c-ares integration
* `net_conn.*` – non-blocking connection object
* `http_transaction.*` – HTTP state machine
* `scheduler.*` – download job scheduler
* `pconn.*` – persistent connection pool
* CLI and legacy glue (`main`, `retr`, etc)

You may:

* Implement or update async logic in these modules
* Refactor legacy blocking code into the async abstractions

You must not:

* Reintroduce `select`, `poll`, `getaddrinfo`, `sleep`, `alarm` in new paths
* Call `ev_*` directly outside `evloop.c`

### `docs/`

Architecture and component docs.

Important files:

* `docs/overview.md` – big-picture system design
* `docs/design-principles.md` – rules and constraints
* `docs/event-loop.md` – `evloop` abstraction
* `docs/dns-resolver.md` – `dns_cares` details
* `docs/connection-management.md` – `net_conn` lifecycle
* `docs/http-transaction.md` – HTTP state machines
* `docs/scheduler.md` – download scheduler
* `docs/connection-pool.md` – persistent connection pooling
* `docs/cli-integration.md` – CLI and top-level flow

You may update these to reflect behavior changes or new modules.

### `build/`

Meson build directory.

* Do not edit or commit any content from `build/`.

### `tests/` (or equivalent)

Unit and integration tests.

* You may:

  * Add or update tests when you change behavior
  * Use existing tests as behavioral specifications

### `TODO.md`

Live status of async migration and remaining work.

* Read before changes
* Update when you finish tasks or discover new follow-ups

---

## 3. Core Documentation Index

Use these as primary references:

* **Design**

  * [`docs/overview.md`](docs/overview.md) – architecture and component roles
  * [`docs/design-principles.md`](docs/design-principles.md) – non-negotiable rules

* **Components**

  * [`docs/event-loop.md`](docs/event-loop.md) – `evloop` / libev
  * [`docs/dns-resolver.md`](docs/dns-resolver.md) – async DNS / c-ares
  * [`docs/connection-management.md`](docs/connection-management.md) – `net_conn`
  * [`docs/http-transaction.md`](docs/http-transaction.md) – HTTP state machine
  * [`docs/scheduler.md`](docs/scheduler.md) – download scheduler
  * [`docs/connection-pool.md`](docs/connection-pool.md) – connection reuse
  * [`docs/cli-integration.md`](docs/cli-integration.md) – CLI flow

* **Status**

  * [`TODO.md`](TODO.md) – current phase and priorities

---

## 4. Hard Requirements

All changes must respect these.

### DNS

* c-ares is **mandatory**
* All hostname resolution goes through the async resolver layer
* No direct `getaddrinfo`, `gethostbyname`, `gethostbyaddr`, etc

### Event loop

* libev is **mandatory**
* Only `evloop.c` may call `ev_io`, `ev_timer`, `ev_run`, etc
* All other code uses `evloop_*` wrappers

### I/O and concurrency

* No blocking paths:

  * No synchronous `connect` loops
  * No blocking `read`/`write` loops that wait for full bodies
  * No `sleep`, `usleep`, `nanosleep`, `alarm` for timeouts
* All timeouts use event loop timers
* Design must scale to thousands of connections

### Architecture

* State machines + callbacks drive all network operations
* Work per event must remain bounded
* Core runs in a single event-loop thread
* Cross-thread interaction must use safe primitives (e.g. `ev_async` inside `evloop`)

If you violate these, revert the change.

---

## 5. Agent Workflow

### Standard Workflow

1. **Read status**

   * Check [`TODO.md`](TODO.md) for:

     * Current phase
     * Active modules
     * Known issues

2. **Review docs**

   * Event loop: `docs/event-loop.md`
   * DNS: `docs/dns-resolver.md`
   * HTTP: `docs/http-transaction.md`
   * Scheduler/concurrency: `docs/scheduler.md`

3. **Plan the change**

   * Identify the module(s) to touch
   * Ensure the change fits the async architecture and design principles
   * When replacing blocking code, use:

     * `evloop`
     * `dns_cares`
     * `net_conn`
     * `http_transaction`
     * `scheduler`

4. **Implement and test**

   * Modify code in the appropriate module
   * Add or update tests
   * Run:

     ```bash
     meson compile -C build
     meson test -C build
     ```

5. **Update status**

   * Mark completed tasks in `TODO.md`
   * Add concise new tasks if you discover necessary follow-ups

### Things Agents Must Not Do

* Rename top-level directories (`src`, `docs`, `build`, etc)
* Change the build system away from Meson
* Split/merge modules in ways that contradict the docs
* Introduce “temporary” blocking code

---

## 6. Key Design Principles

* All DNS is async via **c-ares** (`dns_cares` layer)
* All I/O is event-driven via **libev** (`evloop` abstraction)
* No blocking calls in network or DNS paths
* Use callbacks and immediate returns; do not wait synchronously
* Timeouts use event loop timers only
* HTTP parsing is incremental and streaming
* Work per event is bounded
* The core runs in a single event-loop thread

---

## 7. Build and Test

From the repo root:

```bash
# First-time setup
meson setup build

# Reconfigure if options change
meson setup build --reconfigure

# Build
meson compile -C build

# Run all tests
meson test -C build

# Example targeted test groups
meson test -C build wget:http
meson test -C build wget:cli

# Verbose tests
meson test -C build --verbose
```

If tests fail after your change:

* Fix the regression, or
* Clearly document the reason and scope in `TODO.md` if the failure is expected and temporary

---

## 8. Blocking Code = Bug

This project is **event-driven by design**.

If you find:

* A direct `getaddrinfo` / `gethostbyname` / `gethostbyaddr`
* A blocking `connect` loop
* `sleep` / `usleep` / `nanosleep` / `alarm` in network code
* Direct `select` / `poll` around sockets

You have found a bug or legacy path.

Agents should either:

* Replace it with non-blocking logic using `evloop`, `dns_cares`, `net_conn`, and `http_transaction`, or
* Record it in `TODO.md` with a short description and location if it cannot be fully migrated in one change

---
