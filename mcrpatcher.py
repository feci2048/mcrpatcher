#!/usr/bin/env python3
import argparse
import subprocess
import shutil
import os
import re
import sys

# Barrier instruction patterns (disassembled form) → replacement opcodes
REPLACEMENTS = {
    # DSB (Data Synchronization Barrier)
    r"^mcr\s+p15,\s*0,\s*r0,\s*c7,\s*c10,\s*4$": bytes.fromhex("0ff07ff5"),
    r"^mcr\s+15,\s*0,\s*r0,\s*cr7,\s*cr10,\s*{\s*4\s*}$": bytes.fromhex("0ff07ff5"),

    # DMB (Data Memory Barrier)
    r"^mcr\s+p15,\s*0,\s*r0,\s*c7,\s*c10,\s*5$": bytes.fromhex("0ff05ff5"),
    r"^mcr\s+15,\s*0,\s*r0,\s*cr7,\s*cr10,\s*{\s*5\s*}$": bytes.fromhex("0ff05ff5"),

    # ISB (Instruction Synchronization Barrier)
    r"^mcr\s+p15,\s*0,\s*r0,\s*c7,\s*c5,\s*4$": bytes.fromhex("0ff06ff5"),
    r"^mcr\s+15,\s*0,\s*r0,\s*cr7,\s*cr5,\s*{\s*4\s*}$": bytes.fromhex("0ff06ff5"),
}


def run(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"Error running: {' '.join(cmd)}\n{result.stderr}")
        sys.exit(1)
    return result.stdout

def install_deps():
    print("Installing dependencies (binutils)...")

    # Simple distro detection
    if os.path.exists("/etc/debian_version"):
        print("Detected Debian/Ubuntu.")
        subprocess.run(["sudo", "apt", "update"], check=False)
        subprocess.run(["sudo", "apt", "install", "-y", "binutils"], check=False)

    elif os.path.exists("/etc/redhat-release") or os.path.exists("/etc/fedora-release"):
        print("Detected RedHat/Fedora.")
        subprocess.run(["sudo", "dnf", "install", "-y", "binutils"], check=False)

    elif os.path.exists("/etc/arch-release"):
        print("Detected Arch Linux.")
        subprocess.run(["sudo", "pacman", "-Sy", "--noconfirm", "binutils"], check=False)

    elif os.path.exists("/etc/alpine-release"):
        print("Detected Alpine Linux.")
        subprocess.run(["sudo", "apk", "add", "binutils"], check=False)

    else:
        print("Unsupported or undetected distro. Please install `binutils` manually.")
        sys.exit(1)

    print("Done.")
    sys.exit(0)

def get_text_segment_info(elf_file):
    readelf_out = run(["readelf", "-S", elf_file])
    for line in readelf_out.splitlines():
        if ".text" in line:
            parts = line.split()
            addr_idx = parts.index(".text") + 2
            offset_idx = addr_idx + 2
            vaddr = int(parts[addr_idx], 16)
            foffset = int(parts[offset_idx], 16)
            return vaddr, foffset
    raise RuntimeError("Couldn't find .text section in ELF file.")

def parse_objdump(objdump_out):
    matches = []
    for line in objdump_out.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+([0-9a-f ]+)\s+(.*)$', line)
        if match:
            addr = int(match.group(1), 16)
            mnemonic = match.group(3)
            for pattern, replacement in REPLACEMENTS.items():
                if re.match(pattern, mnemonic.strip(), re.IGNORECASE):
                    matches.append((addr, replacement, mnemonic.strip()))
    return matches

def find_segment_mapping(elf_file, va):
    output = run(["readelf", "-l", elf_file])
    for line in output.splitlines():
        if "LOAD" in line:
            parts = line.split()
            try:
                p_offset = int(parts[1], 16)
                p_vaddr = int(parts[2], 16)
                p_memsz = int(parts[5], 16)
            except (ValueError, IndexError):
                continue
            if p_vaddr <= va < p_vaddr + p_memsz:
                return va - p_vaddr + p_offset
    raise RuntimeError(f"No LOAD segment contains VA 0x{va:x}")

def apply_patches(infile, outfile, base_addr, base_offset, patches):
    with open(infile, "rb") as f:
        data = bytearray(f.read())

    for va, patch, asm in patches:
        offset = find_segment_mapping(infile, va)
        original = data[offset:offset+4]
        print(f"Patching: VA=0x{va:x}, offset=0x{offset:x}, {asm} → {patch.hex()}")
        data[offset:offset+4] = patch

    with open(outfile, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

    # Verify the patched result
    with open(outfile, "rb") as f:
        for va, patch, asm in patches:
            offset = find_segment_mapping(infile, va)
            f.seek(offset)
            actual = f.read(4)
            if actual != patch:
                print(f"Verification failed at offset 0x{offset:x}: expected {patch.hex()}, got {actual.hex()}")
                sys.exit(1)

    print("All patches applied and verified.")


def main():
    parser = argparse.ArgumentParser(description="Patch deprecated CP15 barrier instructions in ARM ELF binaries.")
    parser.add_argument("infile", nargs="?", help="Input ELF binary")
    parser.add_argument("outfile", nargs="?", help="Output binary (defaults to in-place)")
    parser.add_argument("--install-deps", action="store_true", help="Install required packages")

    args = parser.parse_args()

    if args.install_deps:
        install_deps()

    if not args.infile:
        parser.error("infile is required unless --install-deps is specified.")

    infile = args.infile
    outfile = args.outfile or infile

    print(f"Reading .text section info from {infile}...")
    base_addr, base_offset = get_text_segment_info(infile)

    print("Disassembling .text section...")
    objdump_out = run(["objdump", "-d", "--section=.text", infile])
    patches = parse_objdump(objdump_out)

    if not patches:
        print("No deprecated CP15 barrier instructions found.")
        return

    if outfile != infile:
        print(f"Copying {infile} to {outfile} for patching...")
        shutil.copyfile(infile, outfile)

    apply_patches(outfile, outfile, base_addr, base_offset, patches)
    print("All done.")


if __name__ == "__main__":
    main()

