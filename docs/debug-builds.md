# Debug Builds and Sanitizers

This document explains how to build wget with debug options, debug symbols, and sanitizers.

## Build Options

### Debug Logging

To enable debug logging support (requires `--debug` flag at runtime):

```bash
meson setup build --enable-debug-logging=true
meson compile -C build
```

Then run wget with debug output:
```bash
./build/src/wget --debug https://example.com
```

### Debug Symbols

To build with debug symbols for better debugging experience:

```bash
meson setup build --enable-debug-symbols=true
meson compile -C build
```

This adds `-g` flag to the compiler, enabling debug information in the binary.

### AddressSanitizer (ASAN)

To build with AddressSanitizer for memory error detection, use Meson's built-in sanitizer option:

```bash
meson setup build -Db_sanitize=address
meson compile -C build
```

Note: This requires the ASAN runtime libraries to be installed on your system.

## Combined Builds

You can combine multiple debug options:

```bash
# Debug logging + debug symbols
meson setup build -Denable_debug_logging=true -Denable_debug_symbols=true

# Debug symbols + ASAN (using Meson's built-in option)
meson setup build -Denable_debug_symbols=true -Db_sanitize=address

# Debug logging + debug symbols + ASAN
meson setup build -Denable_debug_logging=true -Denable_debug_symbols=true -Db_sanitize=address
```

## Using Meson's Built-in Options

Meson also provides standard build options that work well with wget:

```bash
# Debug build type (includes -g and optimization level 0)
meson setup build --buildtype=debug

# Debugoptimized build type (-g with -O2)
meson setup build --buildtype=debugoptimized

# Enable debug symbols explicitly
meson setup build --debug=true

# Use different sanitizers
meson setup build -Db_sanitize=address,undefined
```

## Runtime Debug Output

When built with `--enable-debug-logging=true`, you can use the `--debug` flag:

```bash
./build/src/wget --debug --verbose https://example.com
```

This will output detailed debug information about HTTP transactions, DNS resolution, connection handling, and more.

## Testing with Sanitizers

When using ASAN, you may want to set environment variables for better output:

```bash
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=0
./build/src/wget https://example.com
```

## Notes

- Debug logging requires both compile-time support (`--enable-debug-logging`) and runtime flag (`--debug`)
- Debug symbols are useful for debugging crashes with gdb or lldb
- ASAN helps detect memory errors like buffer overflows, use-after-free, memory leaks
- These options can be combined with the standard Meson build options for maximum flexibility