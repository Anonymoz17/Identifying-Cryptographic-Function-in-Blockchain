#!/usr/bin/env python3
"""Tool to examine addresses in binary files.

Useful for analyzing findings from static detection.
Shows what bytes are at a given address and attempts disassembly.

Usage:
    python find_address_in_binary.py <binary_path> <address> [context_bytes]

Example:
    python find_address_in_binary.py bitcoin 0x66c 64
    python find_address_in_binary.py bitcoin 1644 32  # decimal address
"""

import sys
import argparse
from pathlib import Path


def hex_to_int(addr_str):
    """Convert hex or decimal string to integer."""
    if addr_str.startswith("0x") or addr_str.startswith("0X"):
        return int(addr_str, 16)
    try:
        return int(addr_str)
    except ValueError:
        raise ValueError(f"Invalid address: {addr_str}")


def read_bytes_at_offset(binary_path, offset, length=64):
    """Read bytes from binary at given offset."""
    try:
        with open(binary_path, "rb") as f:
            f.seek(offset)
            data = f.read(length)
        return data
    except FileNotFoundError:
        print(f"Error: File not found: {binary_path}")
        return None
    except IOError as e:
        print(f"Error reading file: {e}")
        return None


def format_hex_dump(data, address=0, bytes_per_line=16):
    """Format bytes as hex dump (like xxd)."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        addr = f"0x{address + i:08x}"
        lines.append(f"{addr}:  {hex_part:<48}  {ascii_part}")
    return "\n".join(lines)


def try_disassemble(data, address=0):
    """Try to disassemble bytes using capstone if available."""
    try:
        import capstone

        # Try both x86-64 and x86-32
        architectures = [
            (capstone.CS_ARCH_X86, capstone.CS_MODE_64, "x86-64"),
            (capstone.CS_ARCH_X86, capstone.CS_MODE_32, "x86-32"),
        ]

        for arch, mode, name in architectures:
            md = capstone.Cs(arch, mode)
            md.detail = True

            instructions = list(md.disasm(data, address))
            if instructions:
                return name, instructions

        return None, []

    except ImportError:
        return None, []
    except Exception as e:
        print(f"Disassembly error: {e}")
        return None, []


def get_file_size(binary_path):
    """Get file size in bytes."""
    try:
        return Path(binary_path).stat().st_size
    except Exception:
        return None


def get_section_info(binary_path):
    """Try to get section info from binary (ELF/PE)."""
    try:
        import struct

        with open(binary_path, "rb") as f:
            # Read first 4 bytes to check for ELF or PE
            magic = f.read(4)

            if magic == b"\x7fELF":
                # ELF binary
                f.seek(0)
                return parse_elf_sections(f)
            elif magic[:2] == b"MZ":
                # PE binary
                f.seek(0)
                return parse_pe_sections(f)
            else:
                return None

    except Exception:
        return None


def parse_elf_sections(f):
    """Parse ELF sections."""
    try:
        import struct

        f.seek(0)
        magic = f.read(4)
        if magic != b"\x7fELF":
            return None

        ei_class = f.read(1)[0]  # 1=32-bit, 2=64-bit
        is_64bit = ei_class == 2

        if is_64bit:
            f.seek(32)
            e_shoff = struct.unpack("<Q", f.read(8))[0]
            e_shnum = struct.unpack("<H", f.read(2))[0]

            sections = []
            for i in range(e_shnum):
                f.seek(e_shoff + i * 64)
                sh_name = struct.unpack("<I", f.read(4))[0]
                sh_type = struct.unpack("<I", f.read(4))[0]
                sh_flags = struct.unpack("<Q", f.read(8))[0]
                sh_addr = struct.unpack("<Q", f.read(8))[0]
                sh_offset = struct.unpack("<Q", f.read(8))[0]
                sh_size = struct.unpack("<Q", f.read(8))[0]

                if sh_type == 1:  # SHT_PROGBITS
                    sections.append(
                        {
                            "offset": sh_offset,
                            "size": sh_size,
                            "addr": sh_addr,
                            "type": "PROGBITS",
                        }
                    )

            return sections
    except Exception:
        pass

    return None


def parse_pe_sections(f):
    """Parse PE sections."""
    # Simplified PE parsing - just get basic info
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Examine addresses in binary files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python find_address_in_binary.py bitcoin 0x66c
  python find_address_in_binary.py bitcoin 0x66c 128
  python find_address_in_binary.py bitcoin 1644 --context 64 --arch x86-64
        """,
    )

    parser.add_argument("binary", help="Path to binary file")
    parser.add_argument("address", help="Address (hex with 0x prefix or decimal)")
    parser.add_argument(
        "-c", "--context", type=int, default=64, help="Number of bytes to display (default: 64)"
    )
    parser.add_argument(
        "--hex-only", action="store_true", help="Only show hex dump, no disassembly"
    )

    args = parser.parse_args()

    # Parse address
    try:
        offset = hex_to_int(args.address)
    except ValueError as e:
        print(f"Error: {e}")
        return 1

    binary_path = args.binary

    # Get file size
    file_size = get_file_size(binary_path)
    if file_size is None:
        print(f"Error: Cannot read file: {binary_path}")
        return 1

    # Validate offset
    if offset >= file_size:
        print(f"Error: Address 0x{offset:x} is beyond file size (0x{file_size:x})")
        return 1

    # Adjust context to not exceed file
    context = min(args.context, file_size - offset)

    print(f"Binary: {binary_path}")
    print(f"File size: 0x{file_size:x} ({file_size} bytes)")
    print(f"Address: 0x{offset:x} ({offset} bytes)")
    print(f"Context: {context} bytes")
    print()

    # Read bytes
    data = read_bytes_at_offset(binary_path, offset, context)
    if data is None:
        return 1

    # Show hex dump
    print("HEX DUMP:")
    print("-" * 70)
    print(format_hex_dump(data, offset))
    print()

    # Try disassembly
    if not args.hex_only:
        arch, instructions = try_disassemble(data, offset)

        if arch and instructions:
            print(f"DISASSEMBLY ({arch}):")
            print("-" * 70)
            for instr in instructions:
                print(f"0x{instr.address:x}:  {instr.mnemonic:10s} {instr.op_str}")

                # Highlight crypto operations
                crypto_ops = ["shl", "shr", "rol", "ror", "xor", "and", "or"]
                if any(op in instr.mnemonic.lower() for op in crypto_ops):
                    print(f"               ↑ Crypto-related operation: {instr.mnemonic}")
            print()
        else:
            print("(Capstone not installed; install with: pip install capstone)")
            print()

    # Show raw bytes
    print("RAW BYTES:")
    print("-" * 70)
    print(data.hex())
    print()

    # Try to identify section
    sections = get_section_info(binary_path)
    if sections:
        print("SECTION INFO:")
        print("-" * 70)
        for section in sections:
            if section["offset"] <= offset < section["offset"] + section["size"]:
                print(f"Found in section at offset 0x{section['offset']:x}")
                print(f"  Size: 0x{section['size']:x}")
                print(f"  Address: 0x{section['addr']:x}")
                print()

    print("TIPS:")
    print("-" * 70)
    print("• Addresses are FILE OFFSETS (position in the binary file)")
    print("• Use this to verify static detection findings")
    print("• Look for crypto patterns: XOR, bit shifts, loops, etc.")
    print("• Use Ghidra (Ctrl+G) to see full function context")

    return 0


if __name__ == "__main__":
    sys.exit(main())
