import hashlib
import logging
from pathlib import Path

from pefile import PE
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64
from unicorn.unicorn import Uc
from unicorn.x86_const import UC_X86_REG_RBX

from unplayplay.consts import (
    AES_KEY_HOOK,
    EMULATOR_SIZES,
    MEM,
    RT_DATA,
    RT_FUNCTIONS,
    SP_CLT_SHA2,
    SP_CLT_VERSION,
    VM_CONSTANTS,
)
from unplayplay.emu import runtime
from unplayplay.emu.addressing import align, rebase
from unplayplay.emu.heap_allocator import HeapAllocator, HeapChunk
from unplayplay.emu.hooks.hook_malloc import hook_malloc
from unplayplay.emu.hooks.hook_stubs import apply_stubs
from unplayplay.emu_session import EmuSession
from unplayplay.exceptions import EmulationError, KeyExtractionError
from unplayplay.seh.seh_hook import seh_hook
from unplayplay.seh.state_builder import build_state

logger = logging.getLogger(__name__)


class KeyEmu:
    def rebase(self, va: int) -> int:
        return rebase(self._image_base, va)

    def __init__(self, source: Path | bytes) -> None:
        sp_client_data: bytes

        if isinstance(source, Path):
            sp_client_data = source.read_bytes()
        elif isinstance(source, bytes):
            sp_client_data = source
        else:
            raise TypeError("source must be a Path or bytes")

        sp_client_sha256 = hashlib.sha256(sp_client_data)

        if sp_client_sha256.digest() != SP_CLT_SHA2:
            raise ValueError(f"SP client mismatch (v{SP_CLT_VERSION})")

        self._pe = PE(data=sp_client_data, fast_load=True)
        self._mapped_image = self._pe.get_memory_mapped_image()

        self._image_base = getattr(self._pe.OPTIONAL_HEADER, "ImageBase")
        self._image_size = align(len(self._mapped_image))

        self._vm_object_transform = self.rebase(RT_FUNCTIONS.VM_OBJECT_TRANSFORM_VA)
        self._vm_runtime_init = self.rebase(RT_FUNCTIONS.VM_RUNTIME_INIT_VA)
        self._aes_key_va = self.rebase(AES_KEY_HOOK.TRIGGER_RIP)
        self._runtime_context_va = self.rebase(RT_DATA.RUNTIME_CONTEXT_VA)
        self._cxx_throw_exception_va = self.rebase(RT_FUNCTIONS.CXX_THROW_EXCEPTION_VA)
        self._init_with_key_va = self.rebase(RT_FUNCTIONS.INIT_WITH_KEY_VA)

        self._seh_state = build_state(self._image_base)

        self._vm_obj_blob = self._build_initial_vm_obj_blob()

    def _create_base_emulator(self) -> tuple[Uc, HeapAllocator]:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        if not isinstance(self._mapped_image, bytes):
            raise EmulationError("Failed to map PE image")

        mu.mem_map(self._image_base, self._image_size)
        mu.mem_write(self._image_base, self._mapped_image)

        logger.debug("PE mapped at 0x%X with size 0x%X", self._image_base, self._image_size)

        heap = HeapAllocator.create(mu, MEM.HEAP_ADDR, MEM.HEAP_SIZE)

        apply_stubs(mu, self._image_base)
        hook_malloc(mu, self._image_base, heap)

        runtime.setup_stack(mu)
        runtime.setup_process_environment(mu)

        mu.hook_add(
            UC_HOOK_CODE,
            seh_hook,
            self._seh_state,
            begin=self._cxx_throw_exception_va,
            end=self._cxx_throw_exception_va,
        )

        return mu, heap

    def _build_initial_vm_obj_blob(self) -> bytes:
        mu, heap = self._create_base_emulator()

        vm_obj = heap.alloc(EMULATOR_SIZES.VM_OBJECT)
        vm_rt_context = heap.alloc(EMULATOR_SIZES.RT_CONTEXT)

        self._init_runtime(mu, vm_obj, vm_rt_context)

        return bytes(vm_obj.read())

    def _create_session(self) -> EmuSession:
        mu, heap = self._create_base_emulator()

        vm_obj = heap.alloc(EMULATOR_SIZES.VM_OBJECT)
        vm_init_value = heap.alloc(EMULATOR_SIZES.INIT_VALUE)

        vm_init_value.write(VM_CONSTANTS.INIT_VALUE)
        vm_obj.write(self._vm_obj_blob)

        session = EmuSession(
            mu=mu,
            vm_obj=vm_obj,
            obfuscated_key=heap.alloc(EMULATOR_SIZES.OBFUSCATED_KEY),
            init_value=vm_init_value,
            derived_key=heap.alloc(EMULATOR_SIZES.DERIVED_KEY),
            captured_aes_key=None,
        )

        mu.hook_add(
            UC_HOOK_CODE,
            self._hook_aes_key,
            session,
            begin=self._aes_key_va,
            end=self._aes_key_va,
        )

        return session

    def _init_runtime(self, uc: Uc, vm_obj: HeapChunk, vm_rt_context: HeapChunk) -> None:
        data = b"\x00" * 8 + self._runtime_context_va.to_bytes(8, "little")
        vm_rt_context.write(data)
        try:
            runtime.emulate_call(
                uc,
                self._vm_runtime_init,
                [
                    vm_obj.ptr,
                    vm_rt_context.ptr,
                    1,
                ],
            )
        except Exception as e:
            raise EmulationError("Failed to initialize vm runtime") from e

    @staticmethod
    def _hook_aes_key(mu: Uc, address: int, size: int, session: EmuSession) -> None:
        rbx = mu.reg_read(UC_X86_REG_RBX)
        if rbx == AES_KEY_HOOK.TRIGGER_RBX:
            rdx = mu.reg_read(UC_X86_REG_RBX)
            logger.debug("AES key hook triggered, capturing key")
            session.captured_aes_key = mu.mem_read(rdx, EMULATOR_SIZES.KEY)
            mu.emu_stop()

    def get_aes_key(self, obfuscated_key: bytes)  -> bytearray:
        session = self._create_session()

        session.obfuscated_key.write(obfuscated_key)

        try:
            runtime.emulate_call(
                session.mu,
                self._vm_object_transform,
                [
                    session.vm_obj.ptr,
                    session.obfuscated_key.ptr,
                    session.derived_key.ptr,
                    session.init_value.ptr,
                ],
            )

            runtime.emulate_call(
                session.mu,
                self._init_with_key_va,
                [
                    session.vm_obj.ptr,
                    session.derived_key.ptr,
                    session.init_value.ptr,
                ],
            )
        except Exception as e:
            raise EmulationError("Emulation failed during AES key extraction") from e

        if session.captured_aes_key is None:
            raise KeyExtractionError("Failed to capture decrypted key")

        return session.captured_aes_key
