import hashlib
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_IMM
from capstone.x86_const import X86_REG_RIP


APP_DIR = Path(r"C:\Program Files\Synthesizer V Studio 2 Pro")
CODE_PATH = APP_DIR / ".analysis" / "text.bin"
RDATA_PATH = APP_DIR / ".analysis" / "rdata.bin"
IMAGE_BASE = 0x140000000
CODE_RVA = 0x1000
RDATA_RVA = 0x11FB000
BOUNDARY_WINDOW = 0x10000
DEFAULT_FUNCTIONS = (0xAB0AF0, 0xAA0C40, 0xCF9470, 0xAFD180)
CODE_SHA256 = "7e181046dc0acd12460166b9a24918c737ae35cc2ad4512bfcb1457c9c3234b6"
RDATA_SHA256 = "01015dfdcd01010cd4bf246b788fddd66f69992f02c77368654a6be7256d08d6"


def load_capture(path, expected):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"Capture fingerprint mismatch: {path}")
    return data


CODE = load_capture(CODE_PATH, CODE_SHA256)
RDATA = load_capture(RDATA_PATH, RDATA_SHA256)
DISASSEMBLER = Cs(CS_ARCH_X86, CS_MODE_64)
DISASSEMBLER.detail = True


def string_at(rva):
    offset = rva - RDATA_RVA
    if not 0 <= offset < len(RDATA):
        return ""
    end = RDATA.find(b"\0", offset, offset + 400)
    if end < 0:
        return ""
    value = RDATA[offset:end]
    if len(value) < 4 or not all(32 <= byte < 127 for byte in value):
        return ""
    return value.decode("ascii")


def bounds(rva):
    offset = rva - CODE_RVA
    if not 0 <= offset < len(CODE):
        raise ValueError("Address is outside captured code")
    start = CODE.rfind(b"\xcc\xcc", max(0, offset - BOUNDARY_WINDOW), offset)
    if start < 0:
        raise ValueError("No preceding padding boundary found")
    start += 2
    while CODE[start] == 0xCC:
        start += 1
    end = CODE.find(b"\xcc\xcc", offset, offset + BOUNDARY_WINDOW)
    if end < 0:
        raise ValueError("No following padding boundary found")
    return start + CODE_RVA, end + CODE_RVA


def instructions(start, end):
    return DISASSEMBLER.disasm(
        CODE[start - CODE_RVA:end - CODE_RVA], IMAGE_BASE + start
    )


def show(start, end):
    for instruction in instructions(start, end):
        annotations = []
        for operand in instruction.operands:
            if operand.type == CS_OP_MEM and operand.mem.base == X86_REG_RIP:
                rva = instruction.address + instruction.size + operand.mem.disp - IMAGE_BASE
                value = string_at(rva)
                annotations.append(f"RVA {rva:#x}" + (f" {value!r}" if value else ""))
            elif operand.type == CS_OP_IMM and instruction.mnemonic in ("call", "jmp"):
                annotations.append(f"RVA {operand.imm - IMAGE_BASE:#x}")
        suffix = " | " + "; ".join(annotations) if annotations else ""
        print(f"{instruction.address - IMAGE_BASE:08x}  {instruction.mnemonic:8} {instruction.op_str}{suffix}")


def function(rva):
    start, end = bounds(rva)
    print(f"\nPadding-derived code range {start:#x}..{end:#x}")
    show(start, end)


def callers(rva):
    offset = CODE.find(b"\xe8")
    while offset >= 0 and offset + 5 <= len(CODE):
        target = CODE_RVA + offset + 5 + struct.unpack_from("<i", CODE, offset + 1)[0]
        if target == rva:
            address = CODE_RVA + offset
            try:
                start, end = bounds(address)
                valid = any(
                    instruction.address == IMAGE_BASE + address
                    and instruction.mnemonic == "call"
                    for instruction in instructions(start, address + 5)
                )
                if valid:
                    print(f"call {address:#x}, candidate caller {start:#x}..{end:#x}")
            except ValueError:
                print(f"Unaligned call candidate {address:#x}")
        offset = CODE.find(b"\xe8", offset + 1)


if __name__ == "__main__":
    for address in DEFAULT_FUNCTIONS:
        function(address)
