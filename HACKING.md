# Agent Guide: Wget Codebase

This guide is for **agents working on the wget codebase**.
It explains the **repo layout**, **what you may modify**, and **current architecture**.

**IMPORTANT STATUS NOTE**: This project is currently in a **transition phase** from synchronous to asynchronous architecture. The HACKING.md documentation describes the **target async architecture**, but much of it is **not yet implemented**. The current codebase is primarily synchronous with some async DNS components.

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

- Preserve the **current architecture** while being aware of the planned async migration
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

Main C implementation of wget.

**Current Architecture** (synchronous with some async DNS):
* `host.c` – DNS resolution with c-ares (partially async)
* `http-transaction.c` – HTTP state machine (synchronous)
* `connect.c` – Connection management (synchronous)
* `retr.c` – Main retrieval logic (synchronous)
* `http.c` – HTTP protocol handling (synchronous)
* `main.c` – CLI entry point

**Planned Async Architecture** (from TODO.md - NOT YET IMPLEMENTED):
* `evloop.*` – libev abstraction
* `dns_cares.*` – c-ares integration
* `net_conn.*` – non-blocking connection object
* `scheduler.*` – download job scheduler
* `pconn.*` – persistent connection pool

You may:

* Implement or update async logic when working on the async migration
* Refactor legacy blocking code into async abstractions when appropriate

You must not:

* Reintroduce `select`, `poll`, `getaddrinfo`, `sleep`, `alarm` in new paths
* Call `ev_*` directly outside `evloop.c` (when async architecture is implemented)

### `docs/`

Architecture and component docs.

**Important files** (note: many describe planned async architecture, not current implementation):

* `docs/overview.md` – big-picture system design (describes planned async architecture)
* `docs/design-principles.md` – rules and constraints (for planned async architecture)
* `docs/event-loop.md` – `evloop` abstraction (planned, not implemented)
* `docs/dns-resolver.md` – `dns_cares` details (planned, not implemented)
* `docs/connection-management.md` – `net_conn` lifecycle (planned, not implemented)
* `docs/http-transaction.md` – HTTP state machines (planned async version)
* `docs/scheduler.md` – download scheduler (planned, not implemented)
* `docs/connection-pool.md` – persistent connection pooling (planned, not implemented)
* `docs/cli-integration.md` – CLI and top-level flow (planned async version)

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

* **Status & Planning**

  * [`TODO.md`](TODO.md) – current phase and priorities (most important reference)

* **Design** (describes planned async architecture)

  * [`docs/overview.md`](docs/overview.md) – planned architecture and component roles
  * [`docs/design-principles.md`](docs/design-principles.md) – rules for planned async architecture

* **Components** (planned async architecture - NOT YET IMPLEMENTED)

  * [`docs/event-loop.md`](docs/event-loop.md) – `evloop` / libev (planned)
  * [`docs/dns-resolver.md`](docs/dns-resolver.md) – async DNS / c-ares (planned)
  * [`docs/connection-management.md`](docs/connection-management.md) – `net_conn` (planned)
  * [`docs/http-transaction.md`](docs/http-transaction.md) – HTTP state machine (planned async version)
  * [`docs/scheduler.md`](docs/scheduler.md) – download scheduler (planned)
  * [`docs/connection-pool.md`](docs/connection-pool.md) – connection reuse (planned)
  * [`docs/cli-integration.md`](docs/cli-integration.md) – CLI flow (planned async version)

---

## 4. Current Architecture vs Planned Requirements

### Current Architecture (Reality)

**DNS**:
* c-ares is available but not fully integrated
* Some DNS resolution uses async c-ares via `host.c`
* Some DNS resolution may still use blocking methods

**I/O and Concurrency**:
* Primarily synchronous with blocking operations
* Uses `select()` for I/O multiplexing in some places
* Contains blocking `connect()`, `read()`, `write()` operations
* Uses `sleep()` and other blocking timeouts

**Architecture**:
* Synchronous "do everything then return" patterns
* No event loop abstraction
* No non-blocking connection management

### Planned Requirements (Target Async Architecture)

**DNS**:
* c-ares will be **mandatory**
* All hostname resolution will go through async resolver layer
* No direct `getaddrinfo`, `gethostbyname`, `gethostbyaddr`, etc

**Event loop**:
* libev will be **mandatory**
* Only `evloop.c` may call `ev_io`, `ev_timer`, `ev_run`, etc
* All other code uses `evloop_*` wrappers

**I/O and concurrency**:
* No blocking paths:

  * No synchronous `connect` loops
  * No blocking `read`/`write` loops that wait for full bodies
  * No `sleep`, `usleep`, `nanosleep`, `alarm` for timeouts
* All timeouts use event loop timers
* Design must scale to thousands of connections

**Architecture**:
* State machines + callbacks drive all network operations
* Work per event must remain bounded
* Core runs in a single event-loop thread
* Cross-thread interaction must use safe primitives (e.g. `ev_async` inside `evloop`)

---

## 5. Agent Workflow

### Standard Workflow

1. **Read status**

   * Check [`TODO.md`](TODO.md) for:

     * Current phase (currently Phase 0 - Audit)
     * Active modules
     * Known issues
   * **Important**: Understand that most async components are NOT YET IMPLEMENTED

2. **Review current code**

   * Examine actual source files in `src/` to understand current implementation
   * Check `TODO.md` to understand what's planned vs what exists
   * Be aware that many docs describe planned async architecture, not current reality

3. **Plan the change**

   * Identify the module(s) to touch
   * Determine if change should:
     * Work within current synchronous architecture, OR
     * Contribute to async migration (if working on Phase 1+ tasks)
   * When working on async migration, follow the planned architecture from `TODO.md`

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

### Commit Message Standards

All commits must follow consistent formatting and content standards:

**Format**:
```
<type>: <description>

<body>
```

**Types**:
- `feat:` - New functionality or features
- `fix:` - Bug fixes or corrections
- `refactor:` - Code restructuring without changing behavior
- `docs:` - Documentation changes only
- `chore:` - Maintenance tasks, build improvements, etc.
- `test:` - Test-related changes only

**Description Requirements**:
- Use imperative mood ("Add", "Fix", "Improve", not "Added", "Fixed", "Improved")
- Keep first line under 50 characters
- Be specific and descriptive
- Start with lowercase letter
- No trailing punctuation

**Body Requirements**:
- Explain the "why" not just the "what"
- Use bullet points for multiple changes
- Reference specific files or functions when relevant
- Include technical details for complex changes

**Examples**:
```
fix: enhance HSTS header parsing and parameter extraction

- Handle valueless flags like includeSubDomains in HSTS headers properly
- Make c_max_age non-const to allow modification during parsing
- Improve parameter extraction to handle URL-encoded values and separators
```

```
feat: enhance test infrastructure and fix continue functionality

- Add CLI test wrapper with multiple test modes (help, version, no-clobber, etc.)
- Create test data files and HTTP server wrapper scripts
- Fix continue functionality with improved range request handling
- Add original_restval tracking for server-ignored range requests
```

**Avoid**:
- Vague messages like "improve documentation" or "fix bug"
- Messages without clear type prefix
- Incomplete or misleading descriptions
- Multiple unrelated changes in one commit

### Things Agents Must Not Do

* Rename top-level directories (`src`, `docs`, `build`, etc)
* Change the build system away from Meson
* Split/merge modules in ways that contradict the docs
* Introduce “temporary” blocking code

---

## 6. Key Design Principles

### Current Architecture (Reality)

* Primarily synchronous operation
* Some async DNS via c-ares in `host.c`
* Blocking I/O operations throughout
* Uses `select()` for I/O multiplexing where needed
* Timeouts use `sleep()` and other blocking methods

### Planned Async Architecture (Target)

* All DNS will be async via **c-ares** (`dns_cares` layer)
* All I/O will be event-driven via **libev** (`evloop` abstraction)
* No blocking calls in network or DNS paths
* Use callbacks and immediate returns; do not wait synchronously
* Timeouts will use event loop timers only
* HTTP parsing will be incremental and streaming
* Work per event will be bounded
* The core will run in a single event-loop thread

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

## 8. Current Status: Transition to Async

This project is **in transition** from synchronous to event-driven architecture.

**Current Reality**:
* The codebase contains significant blocking code
* This is expected during the transition phase
* Blocking code should be gradually replaced as the async migration progresses

**When you find blocking code**:

* A direct `getaddrinfo` / `gethostbyname` / `gethostbyaddr`
* A blocking `connect` loop
* `sleep` / `usleep` / `nanosleep` / `alarm` in network code
* Direct `select` / `poll` around sockets

This is **expected legacy code** during the transition.

Agents should:

* If working on async migration: Replace with non-blocking logic following the planned architecture
* If not working on async migration: Note the location in `TODO.md` for future migration
* Understand that full async migration is a multi-phase process documented in `TODO.md`

---
