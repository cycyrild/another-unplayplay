from pydantic import TypeAdapter

from unplayplay.generated.runtimefunction_data import runtimefunction_data
from unplayplay.generated.runtimefunction_models import RuntimeFunction
from unplayplay.generated.throwinfo_data import throwinfo_data
from unplayplay.generated.throwinfo_models import ThrowInfo
from unplayplay.seh.state import SehRuntimeState

RF_ADAPTER = TypeAdapter(list[RuntimeFunction])
TI_ADAPTER = TypeAdapter(list[ThrowInfo])


def build_state(image_base: int) -> SehRuntimeState:

    runtime_functions_all = RF_ADAPTER.validate_python(runtimefunction_data)
    throw_infos_list = TI_ADAPTER.validate_python(throwinfo_data)

    runtime_functions = sorted(
        runtime_functions_all,
        key=lambda rf: rf.start_rva,
    )

    throw_infos = {ti.struct_rva: ti for ti in throw_infos_list}

    return SehRuntimeState(
        image_base=image_base,
        runtime_functions=runtime_functions,
        throw_infos=throw_infos,
        runtime_function_starts=[rf.start_rva for rf in runtime_functions],
    )
