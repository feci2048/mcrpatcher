# mcrpatcher

**Patch deprecated CP15 `MCR` barrier instructions in 32-bit ARM ELF binaries**

Modern ARM64 Linux kernels running 32-bit ARM (AArch32) binaries will log warnings like:

```
[<timestamp>] "<process name>" (<process PID>) uses deprecated CP15 Barrier instruction at <address>
```

This tool automatically locates and patches these `MCR` barrier instructions, replacing them with the modern, architecturally-correct equivalents (`DMB SY`, `DSB SY`, `ISB`) directly in the binary.

---

## Features

- Detects deprecated `MCR` barrier instructions (`mcr p15, 0, r0, c7, c10, 5`, etc.)
- Supports multiple `objdump` syntaxes (`cr7`, `c7`, `{5}`, `5`)
- Resolves virtual address to file offset using ELF program headers (not section headers)
- Patches in-place or to a new output file
- Verifies the patched result byte-for-byte
- Cross-distro support: Debian, Ubuntu, Fedora, Arch, Alpine

---

## Usage

```bash
# Install dependencies (binutils)
./mcrpatcher.py --install-deps

# Patch in-place
./mcrpatcher.py ./binary

# Patch to a new output file
./mcrpatcher.py ./binary ./binary.patched
```

---

## Notes

- Only barrier instructions are replaced; other `MCR` uses are ignored.
- Binary must be an ELF file for ARM in 32-bit mode.
- Always test patched binaries for correctness and stability.
- Silencing the warnings might work with the appropriate kernel
  ```bash
  echo 'abi.cp15_barrier=2' > /etc/sysctl.d/99-cp15_barrier.conf
  sysctl -p /etc/sysctl.d/99-cp15_barrier.conf
  ```

## License

MIT or public domain — use freely.
