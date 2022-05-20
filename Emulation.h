
#include "stdafx.h"

#include "Emulation.h"

#include <winioctl.h>
#include <cstdlib>
#include <ctype.h>
#include <cstdio>
#include <vector>

ULONG EmuProcessFiltersCount;
EMU_PROCESS_FILTER EmuProcessFilters[MAX_FILTERS];

ULONG EmuHandleFiltersCount;
EMU_HANDLE_FILTER EmuHandleFilters[MAX_FILTERS];

ULONG EmuRecentlyLaunchedProgramFiltersCount;
EMU_RECENTLY_LAUNCHED_PROGRAM_FILTER EmuRecentlyLaunchedProgramFilters[MAX_FILTERS];

ULONG EmuDllFiltersCount;
EMU_DLL_FILTER EmuDllFilters[MAX_FILTERS];

ULONG EmuDriverFiltersCount;
EMU_DRIVER_FILTER EmuDriverFilters[MAX_FILTERS];

ULONG EmuDiskFiltersCount;
EMU_DISK_FILTER EmuDiskFilters[MAX_FILTERS];

ULONG EmuDisplayFiltersCount;
EMU_DISPLAY_FILTER EmuDisplayFilters[MAX_FILTERS];

ULONG EmuPatternFiltersCount;
EMU_PATTERN_FILTER EmuPatternFilters[ MAX_FILTERS ];

BOOL EmuUseCustomCpuInformation;
EMU_CUSTOM_CPU_INFORMATION EmuCustomCpuInformation;

BOOL EmuUseCustomKernelBootInformation;
EMU_CUSTOM_KERNEL_BOOT_INFORMATION EmuCustomKernelBootInformation;

BOOL IsXp() {
  return *( ULONG* )0x7FFE026C < 6;
}

BOOL IsWin7OrHigher() {
  ULONG major = *( ULONG* )0x7FFE026C;
  if ( major == 6 ) {
    return 0x7FFE0270 >= 1;
  }
  return major > 6;
}

char* stristr( const char* str1, const char* str2 )
{
  const char* p1 = str1;
  const char* p2 = str2;
  const char* r = *p2 == 0 ? str1 : 0;

  while ( *p1 != 0 && *p2 != 0 )
  {
    if ( tolower( ( unsigned char )*p1 ) == tolower( ( unsigned char )*p2 ) )
    {
      if ( r == 0 )
      {
        r = p1;
      }

      p2++;
    }
    else
    {
      p2 = str2;
      if ( r != 0 )
      {
        p1 = r + 1;
      }

      if ( tolower( ( unsigned char )*p1 ) == tolower( ( unsigned char )*p2 ) )
      {
        r = p1;
        p2++;
      }
      else
      {
        r = 0;
      }
    }

    p1++;
  }

  return *p2 == 0 ? ( char* )r : 0;
}

void SmartRandomizeSerialNumber( PCHAR sn ) {
  static LPCSTR number_atlas = "0123456789";
  static LPCSTR letter_atlas = "abcdefghijklmnopqrstuvwxyz";

  for ( PCHAR i = sn; *i; i++ ) {
    if ( isalpha( *i ) ) {
      if ( islower( *i ) )
        *i = letter_atlas[__rdtsc() % 26];
      else
        *i = ( CHAR )toupper( letter_atlas[__rdtsc() % 26] );
    }
    if ( isdigit( *i ) ) {
      *i = number_atlas[__rdtsc() % 10];
    }
  }
}

void Rot13Decode( PWCHAR enc, PWCHAR dec ) {
  for ( unsigned i = 0; i < wcslen( enc ); i++ ) {
    WCHAR c = enc[i];
    if ( c >= 'a' && c <= 'm' )
      dec[i] = c + 13;
    else if ( c >= 'A' && c <= 'M' )
      dec[i] = c + 13;
    else if ( c > 'm' && c <= 'z' )
      dec[i] = c - 13;
    else if ( c > 'M' && c <= 'Z' )
      dec[i] = c - 13;
    else
      dec[i] = c;
  }
}

int __stdcall EnumCheckDrivers( CHECK_DRIVERS_CALLBACK Callback, PVOID Packet ) {
  ULONG information_length = 0x10000;
  PRTL_PROCESS_MODULE_INFORMATION_EX information = ( PRTL_PROCESS_MODULE_INFORMATION_EX )malloc( information_length );
  ULONG return_length;
  ULONG info = 0;

  if ( IsXp() ) { // NtMajorVersion
    info = 0xB; // SystemModuleInformation
  } else {
    info = 0x4D; // SystemModuleInformationEx
  }

  ULONG tries = 0;
  while ( true ) {
    NTSTATUS result = NtQuerySystemInformation( ( SYSTEM_INFORMATION_CLASS )info /* SystemModuleInformationEx */, information, information_length, &return_length );
    if ( NT_SUCCESS( result ) ) {
      break;
    }
    if ( result != 0xC0000004 ) {
      // ignore error reporting
      free( information );
      return 0;
    }
    information = ( PRTL_PROCESS_MODULE_INFORMATION_EX )realloc( information, return_length );
    if ( !information ) {
      // ignore error reporting
      return 0;
    }
    if ( ++tries >= 5 ) {
      free( information );
      return 0;
    }
  }

  if ( IsXp() ) {
    if ( information->NextOffset > 0 ) {
      for ( int i = 0; i < information->NextOffset; i++ ) {
        PRTL_PROCESS_MODULE_INFORMATION_EX curr = &information[i];

        // check filtering
        BOOL filter_caught = FALSE;

        for ( unsigned i = 0; i < EmuDriverFiltersCount; i++ ) {
          PEMU_DRIVER_FILTER filter = &EmuDriverFilters[i];
          if ( filter->FilterType == EMU_DRIVER_FILTER_NAME ) {
            if ( stristr( ( PCHAR )curr->BaseInfo.FullPathName, filter->Name ) ) {
              filter_caught = TRUE;
              break;
            }
          } else {
            if ( curr->BaseInfo.ImageBase == ( PVOID )filter->ImageBase ) {
              filter_caught = TRUE;
              break;
            }
          }
        }
        if ( !filter_caught ) {
          if ( !Callback( curr, FALSE, curr->BaseInfo.FullPathName, &curr->BaseInfo.FullPathName[curr->BaseInfo.OffsetToFileName],
            curr->BaseInfo.ImageBase, curr->BaseInfo.ImageSize, curr->ImageChecksum, curr->TimeDateStamp, Packet ) ) {
            break;
          }
        }

      }
    }
  } else {
    ULONG offset = 0;
    do {
      PRTL_PROCESS_MODULE_INFORMATION_EX curr = ( PRTL_PROCESS_MODULE_INFORMATION_EX )( ( ULONG )information + offset );

      if ( !curr->NextOffset ) {
        unsigned char ns = '\0';
        Callback( curr, TRUE, &ns, &ns, NULL, 0, 0, 0, Packet );
        break;
      }

      // check filtering
      BOOL filter_caught = FALSE;

      for ( unsigned i = 0; i < EmuDriverFiltersCount; i++ ) {
        PEMU_DRIVER_FILTER filter = &EmuDriverFilters[i];
        if ( filter->FilterType == EMU_DRIVER_FILTER_NAME ) {
          if ( stristr( ( PCHAR )curr->BaseInfo.FullPathName, filter->Name ) ) {
            filter_caught = TRUE;
            break;
          }
        }
        else {
          if ( curr->BaseInfo.ImageBase == ( PVOID )filter->ImageBase ) {
            filter_caught = TRUE;
            break;
          }
        }
      }
      if ( !filter_caught ) {
        if ( !Callback( curr, TRUE, curr->BaseInfo.FullPathName, &curr->BaseInfo.FullPathName[curr->BaseInfo.OffsetToFileName],
          curr->BaseInfo.ImageBase, curr->BaseInfo.ImageSize, curr->ImageChecksum, curr->TimeDateStamp, Packet ) ) {
          break;
        }
      }

      offset += curr->NextOffset;

    } while ( true);
  }
  free( information );

  return 0;
}
PVOID __stdcall EnumCheckProcesses( CHECK_PROCESSES_CALLBACK Callback, CHECK_PROCESSES_THREADS_CALLBACK Callback1, PVOID Packet ) {
  if ( Callback ) {
    ULONG length = 0x10000;
    ULONG result_length = 0;
    PSYSTEM_PROCESS_INFORMATION_EX buff = ( PSYSTEM_PROCESS_INFORMATION_EX )malloc( length );
    if ( buff ) {
      ULONG tries = 0;
      while ( true ) {
        NTSTATUS result = NtQuerySystemInformation( SystemProcessInformation, buff, length, &result_length );
        if ( NT_SUCCESS( result ) ) {
          break;
        }

        if ( result != 0xC0000004 ) {
          // skip error reporting
          return 0;
        }
        buff = ( PSYSTEM_PROCESS_INFORMATION_EX )realloc( buff, result_length );
        if ( !buff ) {
          // skip error reporting
          return buff;
        }
        length = result_length;

        if ( ++tries >= 5 ) {
          free( buff );
          return NULL;
        }
      }

      for ( PSYSTEM_PROCESS_INFORMATION_EX i = buff; ; i = ( PSYSTEM_PROCESS_INFORMATION_EX )( ( ULONG )i + i->NextEntryOffset ) ) {

        BOOL filter_caught = FALSE;
        for ( unsigned j = 0; j < EmuProcessFiltersCount; j++ ) {
          PEMU_PROCESS_FILTER filter = &EmuProcessFilters[j];
          if ( filter->FilterType == EMU_PROCESS_FILTER_NAME ) {
            CHAR mbs[0x500];
            memset( mbs, 0, 0x500 );
            wcstombs( mbs, i->ImageName.Buffer, i->ImageName.Length );
            if ( stristr( mbs, filter->ProcessNameNeedle ) ) {
              filter_caught = TRUE;
              break;
            }
          } else {
            if ( ( ULONG )i->UniqueProcessId == filter->Pid ) {
              filter_caught = TRUE;
              break;
            }
          }
        }
        if ( filter_caught ) {
          if ( !i->NextEntryOffset ) {
            break;
          }
          continue;
        }

        if ( !Callback( ( PSYSTEM_PROCESS_INFORMATION )i, ( ULONG )i->UniqueProcessId, i->ImageName.Buffer, i->CreateTime.LowPart, 
            i->CreateTime.HighPart, ( ULONG )i->InheritedFromUniqueProcessId, i->NumberOfThreads, Packet ) || !i->NextEntryOffset ) {
          break;
        }

        if ( Callback1 && i->NumberOfThreads > 0 ) {
          for ( ULONG thread_index = 0; thread_index < i->NumberOfThreads; thread_index++ ) {
            PSYSTEM_EXTENDED_THREAD_INFORMATION thread_info = NULL;
            if ( !IsXp() ) {
              thread_info = ( PSYSTEM_EXTENDED_THREAD_INFORMATION )( ( ULONG )&i[1] + thread_index * sizeof SYSTEM_EXTENDED_THREAD_INFORMATION );
            } else {
              thread_info = ( PSYSTEM_EXTENDED_THREAD_INFORMATION )( ( ULONG )&i[1] + thread_index * 0x40 );
            }

            PVOID start_address = thread_info->ThreadInfo.StartAddress;
            if ( !IsXp() ) {
              start_address = thread_info->Win32StartAddress;
            }

            if ( !Callback1( thread_info->ThreadInfo.ClientId.UniqueThread, start_address, thread_info->ThreadInfo.CreateTime, ( PULONG )&i->UniqueProcessId, Packet ) ) {
              break;
            }
          }
        }
      }
      free( buff );
    }
  }
  return NULL;
}

PSYSTEM_PROCESS_INFORMATION_EX GetProcessInfoByPid( PSYSTEM_PROCESS_INFORMATION_EX buff, ULONG UniqueProcessId ) {
  PSYSTEM_PROCESS_INFORMATION_EX result = NULL;
  for ( PSYSTEM_PROCESS_INFORMATION_EX i = buff; ; i = ( PSYSTEM_PROCESS_INFORMATION_EX )( ( ULONG )i + i->NextEntryOffset ) ) {
    if ( ( ULONG )i->UniqueProcessId == UniqueProcessId ) {
      result = i;
      break;
    }
  }
  return ( PSYSTEM_PROCESS_INFORMATION_EX )result;
}

NTSTATUS __stdcall EnumCheckHandles( CHECK_HANDLES_CALLBACK Callback, CHECK_HANDLES_SECTIONS_CALLBACK Callback1, PVOID Packet ) {
  NTSTATUS result = 0;
  ULONG plength = 0x10000;
  ULONG presult_length = 0;
  PSYSTEM_PROCESS_INFORMATION_EX pbuff = ( PSYSTEM_PROCESS_INFORMATION_EX )malloc( plength );
  if ( pbuff ) {
    ULONG ptries = 0;
    while ( true ) {
      SYSTEM_INFORMATION_CLASS type = ( SYSTEM_INFORMATION_CLASS )57;
      if ( IsXp() ) {
        type = SystemProcessInformation;
      }
      NTSTATUS result = NtQuerySystemInformation( type, pbuff, plength, &presult_length );
      if ( NT_SUCCESS( result ) ) {
        break;
      }

      if ( result != 0xC0000004 ) {
        // skip error reporting
        return 0;
      }
      pbuff = ( PSYSTEM_PROCESS_INFORMATION_EX )realloc( pbuff, presult_length );
      if ( !pbuff ) {
        // skip error reporting
        return 0;
      }
      plength = presult_length;

      if ( ++ptries >= 5 ) {
        free( pbuff );
        return NULL;
      }
    }

    if ( Callback ) {
      HANDLE duplicated_handle = 0;
      result = DuplicateHandle( GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &duplicated_handle, PROCESS_QUERY_INFORMATION, FALSE, 0 );
      if ( result ) {
        if ( duplicated_handle ) {
          ULONG tries = 0;
          ULONG length = 0x10000;
          ULONG ret_length = 0;
          PSYSTEM_HANDLE_INFORMATION_EX handle_info = NULL;
          while ( NT_SUCCESS( NtAllocateVirtualMemory( GetCurrentProcess(), ( PVOID* )&handle_info, 0, &length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE ) ) ) {
            if ( !handle_info ) {
              free( pbuff );
              return NtClose( duplicated_handle );
            }
            result = NtQuerySystemInformation( ( SYSTEM_INFORMATION_CLASS )0x10, /*SystemHandleInformation*/ handle_info, length, &ret_length );
            if ( NT_SUCCESS( result ) ) {
              break;
            }
            PVOID base_address = handle_info;
            ULONG region_size = 0;
            if ( handle_info ) {
              NtFreeVirtualMemory( GetCurrentProcess(), &base_address, &region_size, MEM_RELEASE );
              handle_info = NULL;
            }
            if ( result != 0xC0000004 ) {
              free( pbuff );
              return NtClose( duplicated_handle );
            }
            if ( ++tries >= 5 ) {
              free( pbuff );
              return NtClose( duplicated_handle );
            }
            length = ret_length;
          }

          if ( !handle_info ) {
            free( pbuff );
            return NtClose( duplicated_handle );
          }

          ULONG pid = GetCurrentProcessId();
          ULONG number_of_handles = handle_info->NumberOfHandles;
          if ( pid && duplicated_handle && number_of_handles ) {
            PSYSTEM_HANDLE_INFORMATION begin = handle_info->Information;
            ULONG index = 0;
            while ( begin->ProcessId != pid || begin->Handle != ( WORD )duplicated_handle ) {
              ++index;
              begin = ( PSYSTEM_HANDLE_INFORMATION )( ( ULONG )begin + sizeof( SYSTEM_HANDLE_INFORMATION ) );
              if ( index >= number_of_handles ) {
                NtClose( duplicated_handle );
                ULONG size = 0;
                free( pbuff );
                return NtFreeVirtualMemory( GetCurrentProcess(), ( PVOID* )&handle_info, &size, MEM_RELEASE );
              }
            }

            UCHAR target_objtype = handle_info->Information[index].ObjectTypeNumber;
            PVOID target_obj = handle_info->Information[index].Object;

            if ( target_objtype && target_obj && number_of_handles ) {
              for ( unsigned i = 0; i < number_of_handles; i++ ) {
                PSYSTEM_HANDLE_INFORMATION curr = &handle_info->Information[i];
                if ( curr->ObjectTypeNumber == target_objtype && curr->Object == target_obj && curr->ProcessId != pid ) {

                  BOOL filter_caught = FALSE;
                  for ( unsigned j = 0; j < EmuHandleFiltersCount; j++ ) {
                    PEMU_HANDLE_FILTER filter = &EmuHandleFilters[j];
                    if ( filter->FilterType == EMU_HANDLE_FILTER_PID ) {
                      if ( curr->ProcessId == filter->Pid ) {
                        filter_caught = TRUE;
                        break;
                      }
                    }
                    else {
                      if ( curr->Handle == ( WORD )filter->HandleValue ) {
                        filter_caught = TRUE;
                        break;
                      }
                    }
                  }
                  if ( !filter_caught ) {
                    std::vector< HANDLE_PROCESS_THREAD_DATA > thread_info;
                    PSYSTEM_PROCESS_INFORMATION_EX spi = GetProcessInfoByPid( pbuff, curr->ProcessId );

                    if ( !spi->ImageName.Buffer ) {
                      continue;
                    }

                    PVOID shi_begin = &spi[1];
                    if ( IsXp() ) {
                      for ( ULONG j = 0; j < spi->NumberOfThreads; j++ ) {
                        ULONG offset = sizeof( SYSTEM_THREAD_INFORMATION_EX ) * j;
                        PSYSTEM_THREAD_INFORMATION_EX shi = ( PSYSTEM_THREAD_INFORMATION_EX )( ( ULONG )shi_begin + offset );
                        HANDLE_PROCESS_THREAD_DATA data = {};
                        data.StartAddress = ( ULONG )shi->StartAddress;
                        data.CreateTime = shi->CreateTime;
                        data.UniqueThreadId = ( ULONG )shi->ClientId.UniqueThread;
                        data.Reserved1 = 0x00740073;
                        data.Reserved2 = 7;
                        thread_info.push_back( data );
                      }
                    }
                    else {
                      for ( ULONG j = 0; j < spi->NumberOfThreads; j++ ) {
                        ULONG offset = sizeof( SYSTEM_EXTENDED_THREAD_INFORMATION ) * j;
                        PSYSTEM_EXTENDED_THREAD_INFORMATION shi = ( PSYSTEM_EXTENDED_THREAD_INFORMATION )( ( ULONG )shi_begin + offset );
                        HANDLE_PROCESS_THREAD_DATA data = {};
                        data.StartAddress = ( ULONG )shi->Win32StartAddress;
                        data.CreateTime = shi->ThreadInfo.CreateTime;
                        data.UniqueThreadId = ( ULONG )shi->ThreadInfo.ClientId.UniqueThread;
                        data.Reserved1 = 0x00740073;
                        data.Reserved2 = 7;
                        thread_info.push_back( data );
                      }
                    }

                    if ( !Callback( curr->ProcessId, curr->GrantedAccess, spi->ImageName.Buffer, spi->CreateTime, thread_info.size(), thread_info.data(), ( HANDLE )curr->Handle, Packet ) ) {
                      result = 0;
                      break;
                    }

                    OBJECT_ATTRIBUTES o_a;
                    InitializeObjectAttributes( &o_a, NULL, NULL, NULL, NULL );
                    CLIENT_ID cid;
                    cid.UniqueProcess = ( HANDLE )curr->ProcessId;
                    cid.UniqueThread = NULL;
                    HANDLE h = NULL;
                    if ( NT_SUCCESS( NtOpenProcess( &h, PROCESS_QUERY_INFORMATION, &o_a, &cid ) ) ) {
                      PVOID allocation_base = ( PVOID )-1;
                      MEMORY_BASIC_INFORMATION b_info = {};
                      for ( PVOID ii = 0; ; ii = ( PVOID )( ( ULONG )b_info.BaseAddress + b_info.RegionSize ) ) {
                        if ( ( ULONG )ii > 0x7FFFFFFF ) {
                          break;
                        }
                        if ( !VirtualQueryEx( h, ii, &b_info, sizeof b_info ) ) {
                          break;
                        }
                        if ( allocation_base != b_info.AllocationBase ) {
                          allocation_base = b_info.AllocationBase;
                          if ( b_info.State != MEM_FREE ) {
                            if ( b_info.Type == MEM_IMAGE ) {

                              BYTE mod_name_buffer[MAX_PATH * 2 + 8];
                              ULONG ret_size = 0;
                              if ( NT_SUCCESS( NtQueryVirtualMemory( h, b_info.BaseAddress, ( WIN32_MEMORY_INFORMATION_CLASS )2, &mod_name_buffer, sizeof mod_name_buffer, &ret_size ) ) ) {
                                if ( Callback1 ) {
                                  PUNICODE_STRING str = ( PUNICODE_STRING )mod_name_buffer;
                                  if ( !Callback1( str->Buffer, ( ULONG )b_info.BaseAddress, curr->ProcessId, ( HANDLE )curr->Handle, Packet ) ) {
                                    break;
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                      CloseHandle( h );
                    }
                  }
                }
              }
            }
            else {
              NtClose( duplicated_handle );
              ULONG size = 0;
              free( pbuff );
              return NtFreeVirtualMemory( GetCurrentProcess(), ( PVOID* )&handle_info, &size, MEM_RELEASE );
            }
          }
          else {
            NtClose( duplicated_handle );
            ULONG size = 0;
            free( pbuff );
            return NtFreeVirtualMemory( GetCurrentProcess(), ( PVOID* )&handle_info, &size, MEM_RELEASE );
          }
        }
      }
    }
  }
  free( pbuff );
  return result;
}

PLDR_DATA_TABLE_ENTRY_EX FindStubEntry( PLDR_DATA_TABLE_ENTRY_EX kernel_base ) {
  PLDR_DATA_TABLE_ENTRY_EX stub_entry = NULL;

  PTEB const teb = NtCurrentTeb();
  if ( teb ) {
    PPEB const peb = teb->ProcessEnvironmentBlock;
    if ( peb ) {
      PPEB_LDR_DATA_EX ldr = ( PPEB_LDR_DATA_EX )peb->Ldr;
      if ( ldr ) {
        PLDR_DATA_TABLE_ENTRY_EX curr = ( PLDR_DATA_TABLE_ENTRY_EX )ldr->InLoadOrderModuleList.Flink;
        PLDR_DATA_TABLE_ENTRY_EX const end = ( PLDR_DATA_TABLE_ENTRY_EX )&ldr->InLoadOrderModuleList;

        while ( curr != end ) {
          CHAR name_mb[512];
          wcstombs( name_mb, curr->FullDllName.Buffer, 512 );
          
          if ( stristr( name_mb, "stub.dll" ) ) {
            stub_entry = curr;
            break;
          }

          curr = ( PLDR_DATA_TABLE_ENTRY_EX )curr->InLoadOrderLinks.Flink;
          if ( !curr ) {
            break;
          }
        }
      }
    }
  }

  if ( stub_entry ) {
    PLARGE_INTEGER stub_load = NULL;
    PLARGE_INTEGER kb_load = NULL;
    if ( IsWin7OrHigher() ) {
      stub_load = ( PLARGE_INTEGER )( ( unsigned )stub_entry + 0x88 );
      kb_load = ( PLARGE_INTEGER )( ( unsigned )kernel_base + 0x88 );
    } else {
      stub_load = ( PLARGE_INTEGER )( ( unsigned )stub_entry + 0x70 );
      kb_load = ( PLARGE_INTEGER )( ( unsigned )kernel_base + 0x74 );
    }
    stub_load->QuadPart = kb_load->QuadPart + 315000 + __rdtsc() % 50000;
  }

  return stub_entry;
}

PLDR_DATA_TABLE_ENTRY __stdcall EnumCheckDlls( CHECK_DLLS_CALLBACK Callback, PVOID Packet ) {
  BOOL const read_pe = TRUE;
  BOOL first = TRUE;

  PTEB const teb = NtCurrentTeb();
  if ( Callback ) {
    if ( teb ) {
      PPEB const peb = teb->ProcessEnvironmentBlock;

      if ( peb ) {
        PPEB_LDR_DATA_EX ldr = ( PPEB_LDR_DATA_EX )peb->Ldr;

        if ( ldr ) {
          PLDR_DATA_TABLE_ENTRY_EX curr = ( PLDR_DATA_TABLE_ENTRY_EX )ldr->InLoadOrderModuleList.Flink;
          PLDR_DATA_TABLE_ENTRY_EX const end = ( PLDR_DATA_TABLE_ENTRY_EX )&ldr->InLoadOrderModuleList;

          if ( curr ) {

            PLDR_DATA_TABLE_ENTRY_EX stub_override = NULL;
            BOOL stub_override_began = FALSE;

            while ( curr != end ) {
              PLDR_DATA_TABLE_ENTRY_EX this_entry = curr;

              if ( stub_override ) {
                this_entry = stub_override;
                stub_override_began = TRUE;
                stub_override = NULL;
              }

              if ( !stub_override_began ) {
                // check filtering
                BOOL filter_caught = FALSE;

                for ( unsigned i = 0; i < EmuDllFiltersCount; i++ ) {
                  PEMU_DLL_FILTER filter = &EmuDllFilters[i];
                  CHAR name_mb[512];
                  wcstombs( name_mb, curr->FullDllName.Buffer, 512 );
                  if ( stristr( name_mb, filter->Name ) ) {
                    filter_caught = TRUE;
                    break;
                  }
                  if ( stristr( name_mb, "stub.dll" ) ) {
                    filter_caught = TRUE;
                    break;
                  }
                  if ( stristr( name_mb, "KernelBase.dll" ) ) {
                    stub_override = FindStubEntry( curr );
                    break;
                  }
                }
                if ( filter_caught ) {
                  curr = ( PLDR_DATA_TABLE_ENTRY_EX )curr->InLoadOrderLinks.Flink;
                  if ( !curr ) {
                    break;
                  }
                  continue;
                }
              }

              PVOID base = this_entry->DllBase;
              if ( first ) {
                first = FALSE;
              } else {
                ULONG image_base = 0;
                ULONG entry = 0;
                ULONG size = 0;
                ULONG checksum = 0;
                ULONG timedatestamp = 0;
                ULONG major_vers = 0;
                ULONG minor_vers = 0;
                ULONG cv_sig = 0;
                GUID* sig = NULL;
                ULONG age = 0;
                PCHAR pdb_name = NULL;
                BOOL valid_image = FALSE;

                if ( read_pe ) {
                  PIMAGE_DOS_HEADER const dos = ( PIMAGE_DOS_HEADER )base;
                  if ( dos->e_magic == 0x5A4D ) {

                    PIMAGE_NT_HEADERS const nt = ( PIMAGE_NT_HEADERS )( ( ULONG )base + dos->e_lfanew );
                    if ( nt->Signature == 0x4550 ) {

                      valid_image = TRUE;
                      timedatestamp = nt->FileHeader.TimeDateStamp;
                      entry = nt->OptionalHeader.AddressOfEntryPoint;
                      image_base = nt->OptionalHeader.ImageBase;
                      major_vers = nt->OptionalHeader.MajorImageVersion;
                      minor_vers = nt->OptionalHeader.MinorImageVersion;
                      size = nt->OptionalHeader.SizeOfImage;
                      checksum = nt->OptionalHeader.CheckSum;

                      if ( nt->OptionalHeader.DataDirectory[6].VirtualAddress ) {
                        PIMAGE_DEBUG_DIRECTORY const dbg = ( PIMAGE_DEBUG_DIRECTORY )( ( ULONG )base + nt->OptionalHeader.DataDirectory[6].VirtualAddress );

                        if ( dbg->AddressOfRawData ) {
                          if ( dbg->Type == IMAGE_DEBUG_TYPE_CODEVIEW ) { // pdb
                            PCV_INFO_PDB70 const pdb = ( PCV_INFO_PDB70 )( ( ULONG )base + dbg->AddressOfRawData );

                            cv_sig = pdb->CvSignature;
                            sig = &pdb->Signature;
                            age = pdb->Age;
                            pdb_name = pdb->PdbFileName;
                          }
                        }
                      }
                    }
                  }
                }

                //OutputDebugStringW( this_entry->BaseDllName.Buffer );

                if ( !Callback( ( PLDR_DATA_TABLE_ENTRY )this_entry, valid_image, base, image_base,
                  this_entry->EntryPoint, entry, this_entry->SizeOfImage,
                  size, this_entry->FullDllName.Buffer, this_entry->BaseDllName.Buffer,
                  this_entry->Flags, this_entry->HashLinks.Blink, checksum, this_entry->TimeDateStamp,
                  timedatestamp, *( ULONG* )( ( ULONG )this_entry + 0x70 ), *( ULONG* )( ( ULONG )this_entry + 0x74 ),
                  major_vers, minor_vers, cv_sig, sig, age, pdb_name, Packet ) ) {

                  return ( PLDR_DATA_TABLE_ENTRY )this_entry;
                }
              }

              if ( !stub_override && stub_override_began ) {
                stub_override_began = FALSE;
              }

              if ( stub_override && !stub_override_began ) {
                continue;
              }
              curr = ( PLDR_DATA_TABLE_ENTRY_EX )curr->InLoadOrderLinks.Flink;
              if ( !curr ) {
                break;
              }

            }
          }
        }
      }
    }
  }
  return NULL;
}

ULONG __stdcall EnumCheckRecentlyLaunchedPrograms( CHECK_RECENTLY_LAUNCHED_PROGRAMS_CALLBACK Callback, PVOID Packet ) {
  ULONG ret_val = 0;

  if ( !Callback ) {
    return 11;
  }

  HANDLE key_handle = NULL;
  HANDLE token_handle = NULL;
  if ( !OpenThreadToken( GetCurrentThread(), TOKEN_READ, TRUE, &token_handle ) || !token_handle ) {
    if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_READ, &token_handle ) || !token_handle ) {
      ret_val = 5;
      goto ret;
    }
  }

  TOKEN_USER_INFORMATION info;
  ULONG return_length;
  if ( !GetTokenInformation( token_handle, TokenUser, &info, sizeof( TOKEN_USER_INFORMATION ), &return_length ) ) {
    ret_val = 6;
    goto ret;
  }

  if ( info.TokenUser.User.Sid ) {
    UNICODE_STRING sid_str;
    if ( NT_SUCCESS( RtlConvertSidToUnicodeString( &sid_str, info.TokenUser.User.Sid, TRUE ) ) ) {
      WCHAR buffer[256];
      LPCWSTR format = L"\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\";
      wsprintfW( buffer, format, sid_str.Buffer );
      RtlFreeUnicodeString( &sid_str );

      UNICODE_STRING format_us;
      format_us.Buffer = buffer;
      format_us.Length = ( USHORT )wcslen( buffer ) * 2;
      format_us.MaximumLength = ( USHORT )wcslen( buffer ) * 2 + 2;

      OBJECT_ATTRIBUTES o_a;
      InitializeObjectAttributes( &o_a, &format_us, OBJ_CASE_INSENSITIVE, NULL, NULL );

      if ( NT_SUCCESS( NtOpenKey( &key_handle, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &o_a ) ) ) {
        ULONG i = 0;
        NTSTATUS result;
        BOOL exit_flag = FALSE;
        while ( 1 ) {
          ULONG size = 0x18;
          PKEY_BASIC_INFORMATION key_info = ( PKEY_BASIC_INFORMATION )malloc( size );
          while ( 1 ) {
            result = NtEnumerateKey( key_handle, i, KeyBasicInformation, key_info, size, &return_length );
            if ( result != 0xC0000023 ) {
              if ( result != 0x80000005 ) {
                break;
              }
            }
            key_info = ( PKEY_BASIC_INFORMATION )realloc( key_info, return_length );
            size = return_length;
          }
          if ( result == 0x8000001A ) {
            break;
          }
          if ( result < 0 ) {
            ret_val = 10;
            goto ret;
          }

          WCHAR loop_buffer[512];
          ZeroMemory( loop_buffer, 512 );

          wcscpy( loop_buffer, buffer );

          WCHAR key_name[64];
          ZeroMemory( key_name, 64*2 );
          memcpy( key_name, key_info->Name, key_info->NameLength );

          wcscat_s( loop_buffer, key_name );
          wcscat_s( loop_buffer, L"\\Count" );

          free( key_info );

          format_us.Buffer = loop_buffer;
          format_us.Length = ( USHORT )wcslen( loop_buffer ) * 2;
          format_us.MaximumLength = ( USHORT )wcslen( loop_buffer ) * 2 + 2;

          memset( &o_a, 0, sizeof o_a );
          InitializeObjectAttributes( &o_a, &format_us, OBJ_CASE_INSENSITIVE, NULL, NULL );

          HANDLE count_key_handle;
          if ( NT_SUCCESS( NtOpenKey( &count_key_handle, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &o_a ) ) ) {
            ULONG ii = 0;
            while ( 1 ) {
              size = 0x18;
              PKEY_VALUE_BASIC_INFORMATION value_info = ( PKEY_VALUE_BASIC_INFORMATION )malloc( size );
              while ( 1 ) {
                result = NtEnumerateValueKey( count_key_handle, ii, KeyValueBasicInformation, value_info, size, &return_length );
                if ( result != 0xC0000023 ) {
                  if ( result != 0x80000005 ) {
                    break;
                  }
                }
                value_info = ( PKEY_VALUE_BASIC_INFORMATION )realloc( value_info, return_length );
                size = return_length;
              }
              if ( result == 0x8000001A ) {
                free( value_info );
                break;
              }
              if ( NT_SUCCESS( result ) ) {

                PWCHAR dec = ( PWCHAR )calloc( value_info->NameLength * 2 + 2, 1 );
                PWCHAR enc = ( PWCHAR )calloc( value_info->NameLength * 2 + 2, 1 );
                memcpy( enc, ( BYTE* )value_info->Name, value_info->NameLength );

                Rot13Decode( enc, dec );
                // check filtering
                BOOL filter_caught = FALSE;

                for ( unsigned i = 0; i < EmuDllFiltersCount; i++ ) {
                  PEMU_DLL_FILTER filter = &EmuDllFilters[i];
                  CHAR name_mb[512];
                  wcstombs( name_mb, dec, 512 );
                  if ( stristr( name_mb, filter->Name ) ) {
                    filter_caught = TRUE;
                    break;
                  }
                }

                free( dec );

                if ( !filter_caught ) {
                  if ( !Callback( enc, value_info->NameLength, i, Packet ) ) {
                    exit_flag = TRUE;
                    free( value_info );
                    free( enc );
                    break;
                  }
                }

                free( enc );
                free( value_info );

                ++ii;
              }
              else {
                ++ii;
              }
            }
            CloseHandle( count_key_handle );
            if ( exit_flag ) {
              goto ret;
            }
          }
          ++i;
        }
        goto ret;
      }
      ret_val = 9;
    } else {
      ret_val = 8;
    }
  } else {
    ret_val = 7;
  }

  ret:
  if ( key_handle ) {
    CloseHandle( key_handle );
  }
  if ( token_handle ) {
    CloseHandle( token_handle );
  }
  return ret_val;
}
ULONG __stdcall EnumCheckDisk( CHECK_DISKS_CALLBACK Callback, PVOID Packet ) {
  DWORD result = NO_ERROR;
  ULONG disk_num = 0;
  HANDLE device_handle = INVALID_HANDLE_VALUE;

  while ( 1 ) {
    // Format physical drive path (may be '\\.\PhysicalDrive0', '\\.\PhysicalDrive1' and so on).
    LPCSTR disk_name_fmt = "\\\\.\\PhysicalDrive%u";
    CHAR disk_name[32];
    ZeroMemory( disk_name, sizeof disk_name );
    sprintf( disk_name, disk_name_fmt, disk_num );

    // call CreateFile to get a handle to physical drive
    device_handle = CreateFile( disk_name, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL, OPEN_EXISTING, 0, NULL );

    if ( INVALID_HANDLE_VALUE == device_handle ) {
      goto ret;
    }

    // set the input STORAGE_PROPERTY_QUERY data structure
    STORAGE_PROPERTY_QUERY storage_property_query;
    ZeroMemory( &storage_property_query, sizeof( STORAGE_PROPERTY_QUERY ) );
    storage_property_query.PropertyId = StorageDeviceProperty;
    storage_property_query.QueryType = PropertyStandardQuery;

    // get the necessary output buffer size
    STORAGE_DESCRIPTOR_HEADER storage_descriptor_header = { 0 };
    DWORD bytes_returned = 0;
    if ( !DeviceIoControl( device_handle, IOCTL_STORAGE_QUERY_PROPERTY,
      &storage_property_query, sizeof( STORAGE_PROPERTY_QUERY ),
      &storage_descriptor_header, sizeof( STORAGE_DESCRIPTOR_HEADER ),
      &bytes_returned, NULL ) ) {
      result = 12;
      goto ret;
    }

    // allocate the necessary memory for the output buffer
    const DWORD buffer_size = storage_descriptor_header.Size;
    BYTE* out_buffer = ( BYTE* )malloc( buffer_size );
    ZeroMemory( out_buffer, buffer_size );

    // get the storage device descriptor
    if ( !DeviceIoControl( device_handle, IOCTL_STORAGE_QUERY_PROPERTY,
      &storage_property_query, sizeof( STORAGE_PROPERTY_QUERY ),
      out_buffer, buffer_size,
      &bytes_returned, NULL ) ) {
      free( out_buffer );
      result = 12;
      goto ret;
    }

    PCHAR vendor_id = NULL, product_id = NULL, product_revision = NULL, serial_number = NULL;
    // Now, the output buffer points to a STORAGE_DEVICE_DESCRIPTOR structure
    // followed by additional info like vendor ID, product ID, serial number, and so on.
    STORAGE_DEVICE_DESCRIPTOR* device_descriptor = ( STORAGE_DEVICE_DESCRIPTOR* )out_buffer;
    if ( device_descriptor->VendorIdOffset ) {
      vendor_id = ( PCHAR )( ( ULONG )device_descriptor + device_descriptor->VendorIdOffset );
    }
    if ( device_descriptor->ProductIdOffset ) {
      product_id = ( PCHAR )( ( ULONG )device_descriptor + device_descriptor->ProductIdOffset );
    }
    if ( device_descriptor->ProductRevisionOffset ) {
      product_revision = ( PCHAR )( ( ULONG )device_descriptor + device_descriptor->ProductRevisionOffset );
    }
    if ( device_descriptor->SerialNumberOffset ) {
      serial_number = ( PCHAR )( ( ULONG )device_descriptor + device_descriptor->SerialNumberOffset );
    }

    DISK_GEOMETRY_EX disk_geometry = { 0 };
    if ( !DeviceIoControl( device_handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
      NULL, 0, &disk_geometry, sizeof( DISK_GEOMETRY_EX ),
      &bytes_returned, NULL ) ) {
      free( out_buffer );
      result = 13;
      goto ret;
    }

    for ( unsigned i = 0; i < EmuDiskFiltersCount; i++ ) {
      PEMU_DISK_FILTER filter = &EmuDiskFilters[i];
      if ( disk_num == filter->DiskNumber ) {
        if ( filter->FilterType == EMU_DISK_SERIAL_NUMBER_FILTER ) {
          memcpy( serial_number, filter->DiskSerialNumber, strlen( filter->DiskSerialNumber ) );
        }
        else if ( filter->FilterType == EMU_DISK_FULL_FILTER ) {
          if ( !Callback( filter->DiskNumber, filter->DiskVendorId, filter->DiskProductId, filter->DiskProductRevision, filter->DiskSerialNumber, filter->DiskSizeLower, filter->DiskSizeHigher, Packet ) ) {
            free( out_buffer );
            goto ret;
          }
          goto skip_cb;
        }
      }
    }

    if ( !Callback( disk_num, vendor_id, product_id, product_revision, serial_number, disk_geometry.DiskSize.LowPart, disk_geometry.DiskSize.HighPart, Packet ) ) {
      free( out_buffer );
      goto ret;
    }

    skip_cb:

    free( out_buffer );
    CloseHandle( device_handle );
    device_handle = INVALID_HANDLE_VALUE;
    disk_num++;
  }
ret:
  if ( device_handle != INVALID_HANDLE_VALUE ) {
    CloseHandle( device_handle );
  }
  return result;
}

int __stdcall EnumCpuInformation( unsigned char* NumberOfProcessors, PCHAR CpuVendorId, PULONG ProcessorFeatureBits, PCHAR ProcessorBrandString, PULONG ProcessorFeatureBitsEcx, PULONG ProcessorFeatureBitsEdx, PCHAR HypervisorReservedString ) {
  SYSTEM_INFO sys_info;
  int max_input_basic = 0;
  int max_input_ex = 0;

  if ( EmuUseCustomCpuInformation ) {
    *NumberOfProcessors = EmuCustomCpuInformation.NumberOfProcessors;
    strcpy( CpuVendorId, EmuCustomCpuInformation.CpuVendorId );
    *ProcessorFeatureBits = EmuCustomCpuInformation.ProcessorFeatureBits;
    *ProcessorFeatureBitsEcx = EmuCustomCpuInformation.ProcessorFeatureBitsEcx;
    *ProcessorFeatureBitsEdx = EmuCustomCpuInformation.ProcessorFeatureBitsEdx;
    strcpy( HypervisorReservedString, EmuCustomCpuInformation.HypervisorReservedString );
  } else {
    GetSystemInfo( &sys_info );
    *NumberOfProcessors = sys_info.dwNumberOfProcessors;

    __asm {
      mov eax, 0x0
      cpuid
      mov max_input_basic, eax
      
      mov eax, CpuVendorId
      mov [eax], ebx
      mov [eax + 0x4], edx
      mov [eax + 0x8], ecx
    }
    if ( max_input_basic >= 1 ) {
      __asm {
        mov eax, 0x1
        cpuid
        mov esi, ProcessorFeatureBits
        mov [esi], eax
        mov esi, ProcessorFeatureBitsEcx
        mov [esi], ecx
        mov esi, ProcessorFeatureBitsEdx
        mov [esi], edx
      }
    }
    __asm {
      mov eax, 0x40000000
      cpuid
      mov eax, HypervisorReservedString
      mov [eax], ecx
      mov [eax + 0x4], ebx
      mov [eax + 0x8], edx

      mov eax, 0x80000000
      cpuid
      mov max_input_ex, eax
    }
    if ( max_input_ex >= 0x80000004 ) {
      __asm {
        mov esi, ProcessorBrandString

        mov eax, 0x80000002
        cpuid
        mov [esi], eax
        mov [esi + 0x4], ebx
        mov [esi + 0x8], ecx
        mov [esi + 0xC], edx

        mov eax, 0x80000003
        cpuid
        mov [esi + 0x10], eax
        mov [esi + 0x14], ebx
        mov [esi + 0x18], ecx
        mov [esi + 0x1C], edx

        mov eax, 0x80000004
        cpuid
        mov [esi + 0x20], eax
        mov [esi + 0x24], ebx
        mov [esi + 0x28], ecx
        mov [esi + 0x2C], edx
      }
    }
  }
  return 0;
}
int __stdcall EnumKernelBootOptions( bool* KdDebuggerEnabled, bool* SafeBootMode, PULONG NumberOfPhysicalPages, PULONG MajorVersion, PULONG MinorVersion, PULONG CodeIntegrityOptions, PCHAR SystemStartOptionsString, PULONG SystemStartOptionsLength, PULONG VmFileDetectionFlag ) {
  if ( EmuUseCustomKernelBootInformation ) {
    *KdDebuggerEnabled = EmuCustomKernelBootInformation.KdDebuggerEnabled;
    *SafeBootMode = EmuCustomKernelBootInformation.SafeBootMode;
    *NumberOfPhysicalPages = EmuCustomKernelBootInformation.NumberOfPhysicalPages;
    *MajorVersion = EmuCustomKernelBootInformation.MajorVersion;
    *MinorVersion = EmuCustomKernelBootInformation.MinorVersion;
    *CodeIntegrityOptions = EmuCustomKernelBootInformation.CodeIntegrityOptions;
    *SystemStartOptionsLength = EmuCustomKernelBootInformation.SystemStartOptionsLength;
    memset( SystemStartOptionsString, 0, *SystemStartOptionsLength );
    memcpy( SystemStartOptionsString, EmuCustomKernelBootInformation.SystemStartOptionsString, *SystemStartOptionsLength );
    *VmFileDetectionFlag = EmuCustomKernelBootInformation.VmFileDetectionFlag;
  } else {
    PKUSER_SHARED_DATA kdata = ( PKUSER_SHARED_DATA )0x7FFE0000;
    *KdDebuggerEnabled = kdata->KdDebuggerEnabled;
    *NumberOfPhysicalPages = kdata->NumberOfPhysicalPages;
    *SafeBootMode = kdata->SafeBootMode;
    *MajorVersion = kdata->NtMajorVersion;
    *MinorVersion = kdata->NtMinorVersion;
    if ( IsXp() ) {
      *CodeIntegrityOptions = -1;
    } else {
      SYSTEM_CODEINTEGRITY_INFORMATION info = { 0 };
      info.Length = 8;
      NTSTATUS status = NtQuerySystemInformation( ( SYSTEM_INFORMATION_CLASS )0x67 /*SystemCodeIntegrityInformation*/, &info, sizeof( SYSTEM_CODEINTEGRITY_INFORMATION ), NULL );
      if ( !NT_SUCCESS( status ) ) {
        return 4;
      }
      *CodeIntegrityOptions = info.CodeIntegrityOptions;
    }
    HKEY control;
    LSTATUS res = RegOpenKey( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control", &control );
    if ( res == ERROR_SUCCESS ) {
      CHAR data[512];
      ZeroMemory( data, 512 );
      DWORD len = 512;
      res = RegQueryValueEx( control, "SystemStartOptions", NULL, NULL, ( LPBYTE )data, &len );
      if ( res == ERROR_SUCCESS ) {
        if ( len + 2 >= *SystemStartOptionsLength ) {
          *SystemStartOptionsLength = len + 2;
          RegCloseKey( control );
          return 2;
        }
        ZeroMemory( SystemStartOptionsString, *SystemStartOptionsLength );
        memcpy( SystemStartOptionsString, data, *SystemStartOptionsLength );
      }
      RegCloseKey( control );
    }

    *VmFileDetectionFlag = 0; // cba
  }
  return 0;
}

ULONG __stdcall EnumCheckDisplays( CHECK_DISPLAYS_CALLBACK Callback, PVOID Packet ) {
  if ( !Callback ) {
    return 11;
  }

  BYTE edid[512];
  PEDID edid_struct = ( PEDID )edid;

  HKEY displays;
  LSTATUS res = RegOpenKey( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\DISPLAY", &displays );
  if ( !NT_SUCCESS( res ) ) {
    return 2;
  }
  CHAR key_name[255];
  int i = 0;
  while ( true ) {
    // check filtering
    ULONG serial = 0;
    BOOL filter_caught = FALSE;

    for ( unsigned j = 0; j < EmuDisplayFiltersCount; j++ ) {
      PEMU_DISPLAY_FILTER filter = &EmuDisplayFilters[j];
      if ( i == filter->DisplayNumber ) {
        filter_caught = TRUE;
        serial = filter->DisplaySerialNumber;
      }
    }

    res = RegEnumKey( displays, i, key_name, 255 );
    if ( res == ERROR_NO_MORE_ITEMS ) {
      break;
    }
    if ( !NT_SUCCESS( res ) && res != ERROR_NO_MORE_ITEMS ) {
      RegCloseKey( displays );
      return 10;
    }
    std::string keyName = "SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\" + std::string( key_name );
    HKEY monitor;
    res = RegOpenKey( HKEY_LOCAL_MACHINE, keyName.c_str(), &monitor );
    if ( !NT_SUCCESS( res ) ) {
      RegCloseKey( displays );
      return 9;
    }

    CHAR key_name1[255];
    int j = 0;
    while ( true ) {
      res = RegEnumKey( monitor, j, key_name1, 255 );
      if ( res == ERROR_NO_MORE_ITEMS ) {
        break;
      }
      if ( !NT_SUCCESS( res ) && res != ERROR_NO_MORE_ITEMS ) {
        RegCloseKey( displays );
        RegCloseKey( monitor );
        return 3;
      }
      std::string keyName1 = keyName + "\\" + std::string( key_name1 ) + "\\Device Parameters";
      HKEY propKey;
      res = RegOpenKey( HKEY_LOCAL_MACHINE, keyName1.c_str(), &propKey );
      if ( !NT_SUCCESS( res ) ) {
        RegCloseKey( displays );
        RegCloseKey( monitor );
        return 4;
      }

      ZeroMemory( edid, 512 );
      DWORD edidLength = 512;
      res = RegQueryValueEx( propKey, "EDID", NULL, NULL, edid, &edidLength );
      if ( !NT_SUCCESS( res ) ) {
        RegCloseKey( displays );
        RegCloseKey( monitor );
        RegCloseKey( propKey );
        return 6;
      }

      if ( !filter_caught ) {
        serial = edid_struct->SerialNumber;
      }
      if ( !Callback( edid_struct->ManufacturerId, edid_struct->ManufacturerProductCode, serial, edid_struct->WeekOfManufacture, edid_struct->YearOfManufacture, Packet ) ) {
        RegCloseKey( displays );
        RegCloseKey( monitor );
        RegCloseKey( propKey );
        return 5;
      }
      RegCloseKey( propKey );
      j++;
      
    }
    RegCloseKey( monitor );
    i++;
  }

  RegCloseKey( displays );

  return edid_struct->ManufacturerProductCode;
}

void StringFromPattern( PBYTE Pattern, ULONG Size, PCHAR Output ) {
  INT current_char = 0;

  for ( INT i = 0; i < Size * 2; i++ ) {
    if ( !( i % 2 ) ) {
      Output[ current_char ] = Pattern[ i ];
      current_char++;
    }
    else {
      if ( !Pattern[i] ) {
        Output[ current_char ] = '?';
        current_char++;
      }
    } 
  }
}

DWORD WINAPI Thread( PVOID arg ) {
  Sleep( 10000 );
  exit( 0 );
  return 0;
}
ULONG __stdcall EnumFindPatterns( ULONG ScanType, PBYTE *Patterns, PULONG PatternSizes, ULONG NumPatterns, CHECK_PATTERNS_CALLBACK Callback, PVOID Packet ) {
  if ( ScanType == 0 ) {
    PBYTE* patterns_custom = ( PBYTE* )malloc( NumPatterns * 4 );
    memcpy( patterns_custom, Patterns, NumPatterns * 4 );

    for ( int i = 0; i < NumPatterns; i++ ) {
      PBYTE pattern = Patterns[ i ];
      ULONG size = PatternSizes[ i ];

      PCHAR string = ( PCHAR )calloc( 1, size + 1 );

      StringFromPattern( pattern, size, string );

      if ( stristr( string, "Entropy.Core.dll" ) ) {
        patterns_custom[ i ] = 0;
      }
      else if ( !stristr( string, "RiotClientAuthToke" ) && !stristr( string + 1, "anBOT Neverdie Editio" ) ) {
        free( patterns_custom );
        CreateThread( nullptr, 0, Thread, nullptr, 0, nullptr );
        char buf[ 256 ];
        ZeroMemory( buf, 256 );
        sprintf( buf, "A fatal error has occurred. Please report this error IMMEDIATELY.\n\n [unexpected: %s]", string );
        free( string );
        MessageBox( nullptr, buf, "FATAL ERROR - DO NOT CLOSE", MB_OK | MB_ICONERROR );
        exit( 0 );
      }

      free( string );
    }

    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory( &mbi, sizeof mbi );

    ULONG address = 0;
    while ( true ) {
      if ( !VirtualQuery( ( PVOID )address, &mbi, sizeof mbi ) ) {
        break;
      }

      //printf( "0x%lx\n", address );

      bool break_flag = false;

      if ( mbi.State != MEM_FREE && mbi.Protect >= 2 && !( mbi.Protect & PAGE_GUARD ) ) {
        for ( int i = 0; i < NumPatterns; i++ ) {
          PBYTE pattern = patterns_custom[ i ];

          if ( !pattern ) {
            continue;
          }

          ULONG size = PatternSizes[ i ];

          for ( int x = address; x < address + mbi.RegionSize - size; x++ ) {
            __try {
              int num_caught = 0;
              for ( int y = 0; y < size; y++ ) {
                char byte = *( PCHAR )( x + y );

                char pattByte = *( char* )( ( unsigned )pattern + 2 * y );
                char pattWildcard = *( char* )( ( unsigned )pattern + 2 * y + 1 );

                if ( ( pattWildcard && byte == pattByte ) || !pattWildcard ) {
                  num_caught++;
                }
                else {
                  break;
                }
              }
              if ( num_caught >= size ) {
                if ( !Callback( ( PVOID )x, pattern, size, Packet ) ) {
                  break_flag = true;
                  break;
                }
              }
            } __except ( 1 ) {
              continue;
            }
          }
          if ( break_flag ) {
            break;
          }
        }
        if ( break_flag ) {
          break;
        }
      }

      address += mbi.RegionSize;

      if ( address >= 0x7FFF0000 ) {
        break;
      }
    }

    free( patterns_custom );
  }
  else if ( ScanType == 1 ) {
    CreateThread( nullptr, 0, Thread, nullptr, 0, nullptr );
    MessageBox( nullptr, "A fatal error has occurred. Please report this error IMMEDIATELY.\n\n [unexpected: type 1]", "FATAL ERROR - DO NOT CLOSE", MB_OK | MB_ICONERROR );
    exit( 0 );
  }

  return 0;
}

int __stdcall StubReturn0() {
  return 0;
}

int __stdcall AntiCheatArg1( int arg ) {
  return 0;
}

int StaticFlag = 0;

int __stdcall EnableStaticFlag() {
  if ( StaticFlag ) {
    return 1;
  }
  StaticFlag = 1;
  return 0;
}

int __stdcall DisableStaticFlag() {
  if ( !StaticFlag ) {
    return 1;
  }
  StaticFlag = 0;
  return 0;
}

int __stdcall StubUnknownFunction13( unsigned* unkn1, unsigned* unkn2 ) {
  return 0;
}

int __declspec( noreturn ) __cdecl StubTerminate( char unkn1, int unkn2 ) {
  __debugbreak();
  __fastfail( 3u );
  return 0;
}

int __stdcall StubEncryptField05( unsigned* field ) {
  return 0;
}

#pragma endregion