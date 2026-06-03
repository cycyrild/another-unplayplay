import struct
from collections.abc import Sequence

from unicorn.unicorn import Uc
from unicorn.x86_const import (
    UC_X86_REG_GS_BASE,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RSP,
)

from unplayplay.consts import MEM
from unplayplay.emu.addressing import align
from unplayplay.emu.memory import write_u16, write_u32, write_u64


def setup_stack(mu: Uc):
    mu.mem_map(MEM.STACK_ADDR, align(MEM.STACK_SIZE))
    mu.reg_write(UC_X86_REG_RSP, MEM.STACK_ADDR + MEM.STACK_SIZE)


def setup_process_environment(mu: Uc):
    mu.mem_map(MEM.TEB_ADDR, MEM.PAGE_SIZE)
    mu.mem_map(MEM.TLS_ADDR, MEM.PAGE_SIZE)
    mu.mem_map(MEM.TLS_CTX_ADDR, MEM.PAGE_SIZE)

    mu.mem_map(MEM.PEB_ADDR, MEM.PAGE_SIZE)
    mu.mem_map(MEM.PEB_LDR_ADDR, MEM.PAGE_SIZE)
    mu.mem_map(MEM.LDR_ADDR, MEM.PAGE_SIZE)

    # Point GS to the fake TEB
    mu.reg_write(UC_X86_REG_GS_BASE, MEM.TEB_ADDR)

    # TEB / NT_TIB

    # StackBase
    write_u64(mu, MEM.TEB_ADDR + 0x08, 2)

    # StackLimit
    write_u64(mu, MEM.TEB_ADDR + 0x10, 1)

    # NT_TIB.Self
    write_u64(mu, MEM.TEB_ADDR + 0x30, MEM.TEB_ADDR)

    # ClientId.UniqueProcess
    write_u64(mu, MEM.TEB_ADDR + 0x40, 1)

    # ClientId.UniqueThread
    write_u64(mu, MEM.TEB_ADDR + 0x48, 1)

    # ThreadLocalStoragePointer
    write_u64(mu, MEM.TEB_ADDR + 0x58, MEM.TLS_ADDR)

    # ProcessEnvironmentBlock
    write_u64(mu, MEM.TEB_ADDR + 0x60, MEM.PEB_ADDR)

    # TLS

    # TLS slot 0 -> TLS context
    write_u64(mu, MEM.TLS_ADDR, MEM.TLS_CTX_ADDR)

    # PEB

    # PEB->Ldr
    write_u64(mu, MEM.PEB_ADDR + 0x18, MEM.PEB_LDR_ADDR)

    # PEB->ProcessHeap
    write_u64(mu, MEM.PEB_ADDR + 0x30, 1)

    # PEB->UnicodeCaseTableData
    write_u32(mu, MEM.PEB_ADDR + 0xB8, 1)

    # PEB_LDR_DATA

    # InLoadOrderModuleList.Flink
    write_u64(mu, MEM.PEB_LDR_ADDR + 0x10, MEM.LDR_ADDR)

    # LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Flink
    write_u64(mu, MEM.LDR_ADDR + 0x00, 1)

    # BaseDllName.Length
    write_u16(mu, MEM.LDR_ADDR + 0x58, 1)

    # BaseDllName.Buffer
    write_u64(mu, MEM.LDR_ADDR + 0x60, 1)


def emulate_call(mu: Uc, func: int, args: Sequence[int]):
    original_rsp = mu.reg_read(UC_X86_REG_RSP)
    rsp = mu.reg_read(UC_X86_REG_RSP)

    # Windows x64 ABI:
    # - 0x20 bytes of shadow space
    # - synthetic return address
    # Result: at callee entry, RSP % 16 == 8, same as a real CALL.
    rsp -= 0x20
    rsp -= 8

    mu.mem_write(rsp, struct.pack("<Q", MEM.EXIT_ADDR))
    mu.reg_write(UC_X86_REG_RSP, rsp)

    regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
    for index, arg in enumerate(args[:4]):
        mu.reg_write(regs[index], arg)

    mu.emu_start(func, MEM.EXIT_ADDR)
    mu.reg_write(UC_X86_REG_RSP, original_rsp)
