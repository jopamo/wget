# Agent Guide: Event-Driven Web Downloader Implementation

This guide is for **agents working on the asynchronous web downloader**.  
It explains the **repo layout**, **what you are allowed to touch**, and **how to work safely** in a non-blocking, event-driven codebase.

---

## 0. Agent Contract

If you are an automated agent operating on this repo, follow these rules:

- **Do not**:
  - Introduce blocking I/O (DNS, connect, read, write, sleep, alarm)
  - Change build system type (Meson is mandatory)
  - Add large new dependencies without explicit instructions
  - Modify legal headers, license text, or COPYING
  - Edit generated files or `build/` contents
- **Do**:
  - Preserve existing architecture: **libev + c-ares + non-blocking sockets**
  - Keep code in small, testable units
  - Update docs and tests when you change behavior
  - Run tests relevant to your changes

If you are unsure whether a change is safe, do not make the change.

---

## 1. Quick Start for Agents

### 1.1 First Steps

1. **Check current status**  
   - Open [`TODO.md`](TODO.md) to see:
     - Which phases of the async refactor are done
     - Which modules are in progress
     - Which tasks are reserved or blocked

2. **Understand the architecture**  
   - Read the high-level design in [`docs/overview.md`](docs/overview.md)  
   - Then skim [`docs/design-principles.md`](docs/design-principles.md)

3. **Confirm the build works**  
   From the repo root:
   ```bash
   meson setup build   # if not already configured
   meson compile -C build
   meson test -C build
````

Only after these three steps should you start modifying code.

---

## 2. Repository Layout (for Agents)

You will see at least the following structure (paths relative to repo root):

* `meson.build`
  Top-level build description.
  Agents may:

  * Add new source files or tests when adding new modules
    Agents must not:
  * Change project type or language
  * Remove existing targets without explicit instructions

* `src/`
  Main C implementation of the async web downloader.
  This directory contains:

  * `evloop.*` – libev abstraction
  * `dns_cares.*` – c-ares integration
  * `net_conn.*` – non-blocking connection object
  * `http_transaction.*` – HTTP state machine
  * `scheduler.*` – download job scheduler
  * `pconn.*` – persistent connection pool
  * CLI and legacy glue (`main`, `retr`, etc)

  Agents may:

  * Implement or update async logic in the above modules
  * Refactor legacy blocking code into the new async abstractions

  Agents must not:

  * Reintroduce `select`, `poll`, `getaddrinfo`, `sleep`, `alarm` into new code paths
  * Add direct `ev_*` calls outside `evloop.c`

* `docs/`
  Architecture and component docs. Important for agents:

  * `docs/overview.md` – big-picture system design
  * `docs/design-principles.md` – rules and constraints
  * `docs/event-loop.md` – `evloop` abstraction details
  * `docs/dns-resolver.md` – `dns_cares` design
  * `docs/connection-management.md` – `net_conn` and related APIs
  * `docs/http-transaction.md` – HTTP state machines
  * `docs/scheduler.md` – download scheduler and concurrency rules
  * `docs/connection-pool.md` – persistent connection pooling
  * `docs/cli-integration.md` – CLI and top-level workflow
  
  Agents may:

  * Update docs to reflect behavior changes
  * Add new documentation for new modules or tests

* `build/`
  Meson build directory.
  Agents must not:

  * Edit anything inside `build/` directly
  * Commit `build/` contents

* `tests/` (or similar test layout, depending on repo)
  Contains unit and integration tests, often wired by Meson.
  Agents may:

  * Add or update tests when they change behavior
  * Use tests as examples of how APIs are expected to behave

* `TODO.md`
  Live status of the async migration phases and remaining work.
  Agents should:

  * Read before making changes
  * Append or update tasks if they complete or change scope

---

## 3. Core Documentation Index

Use these documents as your primary references:

* **Core design**

  * [`docs/overview.md`](docs/overview.md) – System architecture and component roles
  * [`docs/design-principles.md`](docs/design-principles.md) – Implementation guidelines and non-negotiable rules

* **Components**

  * [`docs/event-loop.md`](docs/event-loop.md) – `evloop` abstraction around libev
  * [`docs/dns-resolver.md`](docs/dns-resolver.md) – asynchronous DNS via c-ares
  * [`docs/connection-management.md`](docs/connection-management.md) – `net_conn` and connection lifecycle
  * [`docs/http-transaction.md`](docs/http-transaction.md) – HTTP request/response state machine
  * [`docs/scheduler.md`](docs/scheduler.md) – download scheduler and concurrency limits
  * [`docs/connection-pool.md`](docs/connection-pool.md) – persistent connection reuse
  * [`docs/cli-integration.md`](docs/cli-integration.md) – top-level CLI and program flow

* **Tools and tests**
  * [`TODO.md`](TODO.md) – current status, unfinished phases, and priorities

---

## 4. Hard Requirements (Non-Negotiable)

All agents must enforce these constraints in all changes:

* **DNS**

  * c-ares is **mandatory**
  * All host name resolution must go through the async resolver layer
  * No direct calls to `getaddrinfo`, `gethostbyname`, `gethostbyaddr`, etc

* **Event loop**

  * libev is **mandatory**
  * No direct use of `ev_io`, `ev_timer`, `ev_run`, etc outside `src/evloop.c`
  * Everything else uses the `evloop_*` wrappers

* **I/O and concurrency**

  * No blocking paths:

    * No synchronous `connect` loops that wait for completion
    * No blocking `read`/`write` loops that wait for full body
    * No `sleep`, `usleep`, `nanosleep`, `alarm` for timeouts
  * All timeouts use event loop timers
  * System must scale to thousands of connections by design

* **Architecture**

  * State machines and callbacks drive all network operations
  * Work per event must remain bounded
  * Core runs in a single event-loop thread; cross-thread interaction goes through safe primitives (e.g. `ev_async` in `evloop`)

If you introduce blocking behavior or violate these constraints, you must revert the change.

---

## 5. Agent Workflow

### 5.1 Standard Workflow

1. **Read the status**

   * Check [`TODO.md`](TODO.md) for:

     * Which phase is active
     * Which modules are being modified
     * Any open issues (e.g. known flaky tests)

2. **Review relevant docs**

   * For event-loop changes: `docs/event-loop.md`
   * For DNS changes: `docs/dns-resolver.md`
   * For HTTP logic: `docs/http-transaction.md`
   * For concurrency or job management: `docs/scheduler.md`

4. **Plan the change**

   * Decide which module(s) should be updated
   * Ensure the change fits the async architecture and design principles
   * When migrating blocking code:

     * Replace it with calls to `evloop`, `dns_cares`, `net_conn`, `http_transaction`, or `scheduler`, not ad-hoc async logic

5. **Implement and test**

   * Modify code in the appropriate module
   * Add or update tests
   * Run:

     ```bash
     meson compile -C build
     meson test -C build
     ```

6. **Update status**

   * If you complete a task listed in `TODO.md`, mark it done or move it to the appropriate section
   * If you discovered a new follow-up task, add it concisely

### 5.2 What Agents Should Not Do

* Do not:

  * Rename top-level directories (`src`, `docs`, `build`, etc)
  * Change the build system from Meson to something else
  * Split or merge modules in ways that contradict the docs
  * Introduce new blocking code paths “temporarily”

---

## 6. Key Design Principles (Short Version)

* All DNS is async through **c-ares** (`dns_cares` layer)
* All I/O is event-driven through **libev** (`evloop` abstraction)
* No blocking calls in network or DNS paths
* Use callbacks plus immediate returns; never wait synchronously
* Timeouts are implemented using event loop timers only
* HTTP parsing is incremental and streaming
* Work done per event is bounded to avoid starvation
* The core runs in one event-loop thread

---

## 7. Build and Test Process

### 7.1 Building with Meson

From repo root:

```bash
# Configure build directory (first time)
meson setup build

# Reconfigure if needed (e.g., options changed)
meson setup build --reconfigure

# Build
meson compile -C build

# Run all tests
meson test -C build

# Run specific logical test groups
meson test -C build wget:http
meson test -C build wget:cli

# Run tests with verbose output
meson test -C build --verbose
```

Agents must ensure that changes do not break these commands.

### 7.2 Example Test Commands

```bash
# Continue / resume behavior
meson test -C build wget:cli / cli/continue

# HTTPS behavior
meson test -C build wget:cli / cli/https_basic
meson test -C build wget:cli / cli/https_cert_verify

# WARC behavior
meson test -C build wget:cli / cli/warc_basic
meson test -C build wget:cli / cli/warc_multi

# Run tests with malloc perturbation to catch memory bugs
MALLOC_PERTURB_=1 meson test -C build --verbose
```

If a test fails after your change, either fix the regression or clearly document the reason in `TODO.md` if the failure is expected and temporary.

---

## 8. Test Status and Coverage Notes

This section is informational. Agents should not assume it is always up to date.

* **When in doubt, re-run tests**, do not rely on cached or historical status

Coverage expectations:

* HTTP tests cover:

  * Basic downloads, redirects, errors, POST, ranges
  * Multiple downloads and recursive fetches
* CLI tests cover:

  * Options, modes, logging, exit codes, non-interactivity, error handling
* HTTPS tests cover:

  * Certificate verification, custom flags, and error conditions
* WARC tests cover:

  * Creation and structure of archived sessions

When you change HTTP, CLI, HTTPS, or WARC behavior, you should:

* Update or add tests in the relevant area
* Confirm the previous behaviors still pass unless explicitly deprecated

---

## 9. Blocking Code = Bug

This project is **event-driven by design**.

* If you find:

  * A direct `getaddrinfo` call
  * A blocking `connect` loop
  * A `sleep`/`usleep`/`nanosleep` in network code
  * A direct `select`/`poll` around sockets
* Then you have found a bug or a legacy path that must be migrated.

Agents should either:

* Replace it with non-blocking logic that uses `evloop`, `dns_cares`, `net_conn`, and `http_transaction`, or
* Mark it clearly in `TODO.md` with a short description and location if the migration cannot be completed in one change

---

