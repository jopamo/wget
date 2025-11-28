# Agent Guide: Wget Codebase

This guide is for **agents working on the wget codebase**.
It explains the **repo layout**, **what you may modify**, and **current architecture**.

**IMPORTANT STATUS NOTE**: This project uses synchronous I/O architecture with optional asynchronous DNS resolution via c-ares. The implementation focuses on reliability and maintainability while providing good performance for typical download scenarios.

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

**Current Architecture** (synchronous I/O with optional async DNS):
* `host.c` – DNS resolution with optional c-ares support
* `http-transaction.c` – HTTP state machine
* `connect.c` – Connection management
* `retr.c` – Main retrieval logic
* `http.c` – HTTP protocol handling
* `main.c` – CLI entry point

You may:

* Improve existing functionality while maintaining the synchronous architecture
* Add features that work within the current I/O model
* Optimize performance within the synchronous paradigm

You must not:

* Introduce unnecessary complexity or dependencies
* Break existing functionality without thorough testing
* Add features that conflict with the current architecture

### `docs/`

Architecture and component docs.

**Important files**:

* `docs/overview.md` – big-picture system design
* `docs/design-principles.md` – rules and constraints
* `TODO.md` – current status and planned improvements

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

* **Current Implementation**

  * [`src/host.c`](src/host.c) – DNS resolution with optional c-ares
  * [`src/connect.c`](src/connect.c) – Connection management
  * [`src/http.c`](src/http.c) – HTTP protocol handling
  * [`src/retr.c`](src/retr.c) – Main download logic

---

## 4. Current Architecture

### Current Architecture

**DNS**:
* c-ares is optional and provides asynchronous DNS resolution when available
* Falls back to synchronous `getaddrinfo` when c-ares is not available
* Supports both IPv4 and IPv6 address resolution

**I/O and Concurrency**:
* Uses synchronous I/O operations for simplicity and reliability
* Employs appropriate timeouts for network operations
* Handles multiple connections through sequential processing

**Architecture**:
* Straightforward "do everything then return" patterns
* Clear module boundaries and responsibilities
* Focus on reliability and maintainability

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

### Current Architecture

* Uses synchronous I/O operations for simplicity
* Optional asynchronous DNS via c-ares when available
* Clear module boundaries and responsibilities
* Focus on reliability and maintainability
* Appropriate use of timeouts for network operations

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

## 8. Current Status

This project uses a **synchronous I/O architecture** with optional asynchronous DNS resolution.

**Current Implementation**:
* The codebase uses synchronous I/O operations for reliability and simplicity
* DNS resolution can use asynchronous c-ares when available
* The architecture is stable and well-tested

**Design Philosophy**:
* Focus on reliability and maintainability
* Use appropriate timeouts for network operations
* Provide good performance for typical download scenarios
* Keep the codebase straightforward and understandable

---
