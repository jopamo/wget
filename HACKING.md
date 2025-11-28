# Agent Guide: Wget Codebase

This guide is for **agents working on the wget codebase**.
It explains the **repo layout**, **what you may modify**, and **current architecture**.

**IMPORTANT STATUS NOTE**: This project is currently in a **transition phase** from synchronous to asynchronous architecture. The HACKING.md documentation describes the **target async architecture**, but much of it is **not yet implemented**. The current codebase has completed Phases 0-7 of the async migration, with async DNS, event loop, connection management, HTTP transactions, scheduler, connection pool, and CLI integration implemented. Remaining phases (8-9) focus on legacy code removal and testing.

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

**Current Architecture** (async migration in progress - Phases 0-7 completed):
* `host.c` – DNS resolution with c-ares (partially async)
* `http-transaction.c` – HTTP state machine (async)
* `connect.c` – Connection management (synchronous - legacy)
* `retr.c` – Main retrieval logic (synchronous - legacy)
* `http.c` – HTTP protocol handling (synchronous - legacy)
* `main.c` – CLI entry point (async scheduler integration)

**Implemented Async Components** (from TODO.md - Phases 0-7):
* `evloop.*` – libev abstraction (Phase 1)
* `dns_cares.*` – c-ares integration (Phase 2)
* `net_conn.*` – non-blocking connection object (Phase 3)
* `http-transaction.*` – HTTP state machine (Phase 4)
* `scheduler.*` – download job scheduler (Phase 5)
* `pconn.*` – persistent connection pool (Phase 6)
* CLI integration with async scheduler (Phase 7)

You may:

* Implement or update async logic when working on the async migration
* Refactor legacy blocking code into async abstractions when appropriate

You must not:

* Reintroduce `select`, `poll`, `getaddrinfo`, `sleep`, `alarm` in new paths
* Call `ev_*` directly outside `evloop.c` (when async architecture is implemented)

### `docs/`

Architecture and component docs.

**Important files** (note: many describe the implemented async architecture):

* `docs/overview.md` – big-picture system design (describes implemented async architecture)
* `docs/design-principles.md` – rules and constraints (for async architecture)
* `docs/event-loop.md` – `evloop` abstraction (implemented)
* `docs/dns-resolver.md` – `dns_cares` details (implemented)
* `docs/connection-management.md` – `net_conn` lifecycle (implemented)
* `docs/http-transaction.md` – HTTP state machines (implemented async version)
* `docs/scheduler.md` – download scheduler (implemented)
* `docs/connection-pool.md` – persistent connection pooling (implemented)
* `docs/cli-integration.md` – CLI and top-level flow (implemented async version)

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

### Current Architecture (Reality - Async Migration Phases 0-7 Completed)

**DNS**:
* c-ares is **fully integrated** and mandatory for async DNS resolution
* All hostname resolution goes through async `dns_cares` layer
* No direct `getaddrinfo`, `gethostbyname`, `gethostbyaddr` calls in async paths

**Event loop**:
* libev is **mandatory** and fully integrated
* Only `evloop.c` calls `ev_io`, `ev_timer`, `ev_run`, etc
* All other code uses `evloop_*` wrapper abstraction

**I/O and concurrency**:
* Core operations are non-blocking via `net_conn` abstraction
* HTTP transactions use async state machine in `http_transaction`
* Download scheduler manages concurrent jobs with host-based limits
* Persistent connection pool (`pconn`) manages connection reuse
* All timeouts use event loop timers

**Architecture**:
* State machines + callbacks drive all network operations
* Work per event remains bounded
* Core runs in a single event-loop thread
* CLI integration with async scheduler completed

**Legacy Code**:
* Some synchronous code paths still exist for compatibility
* Legacy modules: `connect.c`, `retr.c`, `http.c` (synchronous wrappers)
* Blocking operations gradually being replaced as migration progresses

### Planned Requirements (Target Async Architecture - Phases 8-9)

**DNS**:
* ✅ **COMPLETED** - c-ares fully integrated and mandatory

**Event loop**:
* ✅ **COMPLETED** - libev fully integrated with wrapper abstraction

**I/O and concurrency**:
* ✅ **COMPLETED** - Non-blocking operations via `net_conn`
* ✅ **COMPLETED** - Async HTTP transactions
* ✅ **COMPLETED** - Download scheduler with concurrency limits
* ✅ **COMPLETED** - Persistent connection pool

**Remaining Work** (Phase 8-9):
* Remove or stub all **blocking I/O helpers**
* Remove any remaining direct `select`/`poll` usage
* Remove any residual sleeps, busy loops, or `alarm()`-based timeouts
* Ensure no module touches libev directly (everything uses `evloop_*` wrappers)
* Comprehensive testing, performance optimization, and hardening

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

## 8. Current Status: Async Architecture Live

This project has **successfully completed** the transition from synchronous to event-driven architecture.

**Current Reality**:
* Async architecture is **LIVE AND OPERATIONAL**
* Core async components implemented and tested
* All core tests passing (21/21 Meson tests, 17/17 Python tests)
* Legacy synchronous API preserved as wrapper over async core

**Key Achievements**:
* ✅ Event loop abstraction (`evloop`) with libev
* ✅ Asynchronous DNS resolution (`dns_cares`) with c-ares
* ✅ Non-blocking connection management (`net_conn`)
* ✅ HTTP transaction state machine (`http_transaction`)
* ✅ Download scheduler (`scheduler`) with concurrency limits
* ✅ Persistent connection pool (`pconn`) for connection reuse
* ✅ CLI integration with async scheduler

**Remaining Work** (Phases 8-9):
* Remove or stub all **blocking I/O helpers**
* Remove any remaining direct `select`/`poll` usage
* Remove any residual sleeps, busy loops, or `alarm()`-based timeouts
* Ensure no module touches libev directly (everything uses `evloop_*` wrappers)
* Comprehensive testing, performance optimization, and hardening

For detailed status and remaining tasks, see [`TODO.md`](TODO.md).

---
