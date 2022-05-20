
#include "stdafx.h"

#include <windows.h>

#include "LACE.h"
#include "Emulation.h"

PVOID m_FunctionTable = NULL;
EMU_ERROR Emu_BeginEmulation( PVOID FunctionTable ) {
  if ( FunctionTable ) {
    m_FunctionTable = FunctionTable;

    PCALLBACK_DELEGATE_TABLE table = ( PCALLBACK_DELEGATE_TABLE )FunctionTable;
    table->Written = TRUE;
    table->Callbacks[0] = DisableStaticFlag;
    table->Callbacks[1] = EnableStaticFlag;
    table->Callbacks[2] = AntiCheatArg1;
    table->Callbacks[3] = AntiCheatArg1;
    table->Callbacks[4] = StubReturn0;
    table->Callbacks[5] = StubEncryptField05;
    table->Callbacks[6] = StubTerminate;
    table->Callbacks[7] = EnumCheckDrivers;
    table->Callbacks[8] = EnumCheckProcesses;
    table->Callbacks[9] = EnumCheckHandles;
    table->Callbacks[10] = StubReturn0;
    table->Callbacks[11] = EnumCpuInformation;
    table->Callbacks[12] = EnumCheckDlls;
    table->Callbacks[13] = EnumKernelBootOptions;
    table->Callbacks[14] = EnumCheckRecentlyLaunchedPrograms;
    table->Callbacks[15] = StubReturn0;
    table->Callbacks[16] = StubReturn0;
    table->Callbacks[17] = AntiCheatArg1;
    table->Callbacks[18] = EnumCheckDisk;
    table->Callbacks[19] = StubUnknownFunction13;
    table->Callbacks[20] = StubReturn0;
    table->Callbacks[21] = EnumCheckDisplays;
    table->Callbacks[22] = EnumFindPatterns;

    return EMU_ERROR_SUCCESS;
  }
  return EMU_ERROR_UNKNOWN;
}

EMU_ERROR Emu_EndEmulation() {
  if ( !m_FunctionTable ) {
    return EMU_ERROR_UNKNOWN;
  }

  PCALLBACK_DELEGATE_TABLE table = ( PCALLBACK_DELEGATE_TABLE )m_FunctionTable;
  ZeroMemory( table, sizeof table );

  return EMU_ERROR_SUCCESS;
}

EMU_ERROR Emu_AddProcessFilter( PEMU_PROCESS_FILTER Filter ) {
  if ( EmuProcessFiltersCount >= MAX_FILTERS ) {
    return EMU_ERROR_MAX_FILTERS;
  }
  EmuProcessFilters[EmuProcessFiltersCount] = *Filter;
  EmuProcessFiltersCount++;

  return EMU_ERROR_SUCCESS;
}

EMU_ERROR Emu_AddHandleFilter( PEMU_HANDLE_FILTER Filter ) {
  if ( EmuHandleFiltersCount >= MAX_FILTERS ) {
    return EMU_ERROR_MAX_FILTERS;
  }
  EmuHandleFilters[EmuHandleFiltersCount] = *Filter;
  EmuHandleFiltersCount++;

  return EMU_ERROR_SUCCESS;
}

EMU_ERROR Emu_AddRecentlyLaunchedProgramFilter( PEMU_RECENTLY_LAUNCHED_PROGRAM_FILTER Filter ) {
  if ( EmuRecentlyLaunchedProgramFiltersCount >= MAX_FILTERS ) {
    return EMU_ERROR_MAX_FILTERS;
  }
  EmuRecentlyLaunchedProgramFilters[EmuRecentlyLaunchedProgramFiltersCount] = *Filter;
  EmuRecentlyLaunchedProgramFiltersCount++;

  return EMU_ERROR_SUCCESS;
}

EMU_ERROR Emu_AddDllFilter( PEMU_DLL_FILTER Filter ) {
  if ( EmuDllFiltersCount >= MAX_FILTERS ) {
    return EMU_ERROR_MAX_FILTERS;
  }
  EmuDllFilters[EmuDllFiltersCount] = *Filter;
  EmuDllFiltersCount++;

  return EMU_ERROR_SUCCESS;
}

EMU_ERROR Emu_AddDriverFilter( PEMU_DRIVER_FILTER Filter ) {
  if ( EmuDriverFiltersCount >= MAX_FILTERS ) {
    return EMU_ERROR_MAX_FILTERS;
  }
  EmuDriverFilters[EmuDriverFiltersCount] = *Filter;
  EmuDriverFiltersCount++;

  return EMU_ERROR_SUCCESS;
}

EMU_ERROR Emu_AddDiskFilter( PEMU_DISK_FILTER Filter ) {
  if ( EmuDiskFiltersCount >= MAX_FILTERS ) {
    return EMU_ERROR_MAX_FILTERS;
  }
  EmuDiskFilters[EmuDiskFiltersCount] = *Filter;
  EmuDiskFiltersCount++;

  return EMU_ERROR_SUCCESS;
}

EMU_ERROR Emu_AddDisplayFilter( PEMU_DISPLAY_FILTER Filter ) {
  if ( EmuDisplayFiltersCount >= MAX_FILTERS ) {
    return EMU_ERROR_MAX_FILTERS;
  }
  EmuDisplayFilters[EmuDisplayFiltersCount] = *Filter;
  EmuDisplayFiltersCount++;

  return EMU_ERROR_SUCCESS;
}

EMU_ERROR Emu_AddPatternFilter( PEMU_PATTERN_FILTER Filter ) {
  if ( EmuPatternFiltersCount >= MAX_FILTERS ) {
    return EMU_ERROR_MAX_FILTERS;
  }
  EmuPatternFilters[ EmuPatternFiltersCount ] = *Filter;
  EmuPatternFiltersCount++;

  return EMU_ERROR_SUCCESS;
}

EMU_ERROR Emu_SetCustomCpuInformation( PEMU_CUSTOM_CPU_INFORMATION CpuInformation ) {
  EmuUseCustomCpuInformation = TRUE;
  EmuCustomCpuInformation = *CpuInformation;
  return EMU_ERROR_SUCCESS;
}
EMU_ERROR Emu_SetCustomKernelBootInformation( PEMU_CUSTOM_KERNEL_BOOT_INFORMATION KernelBootInformation ) {
  EmuUseCustomKernelBootInformation = TRUE;
  EmuCustomKernelBootInformation = *KernelBootInformation;
  return EMU_ERROR_SUCCESS;
}

EMU_ERROR Emu_DisableCustomCpuInformation() {
  EmuUseCustomCpuInformation = FALSE;
  return EMU_ERROR_SUCCESS;
}
EMU_ERROR Emu_DisableCustomKernelBootInformation() {
  EmuUseCustomKernelBootInformation = FALSE;
  return EMU_ERROR_SUCCESS;
}
