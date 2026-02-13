/* Binalyze driver interface header. */

#pragma once

#define IREC_DEVICE_TYPE (DWORD)0x8001
#define IREC_FUNCTION_OPEN_PROCESS (DWORD)0x80A

#define IOCTL_IREC_OPEN_PROCESS                                             \
    CTL_CODE(IREC_DEVICE_TYPE, IREC_FUNCTION_OPEN_PROCESS, METHOD_BUFFERED, \
             FILE_ANY_ACCESS)  // 0x80012028

BOOL WINAPI BeDrvOpenProcess(_In_ HANDLE DeviceHandle,
                             _In_ HANDLE ProcessId,
                             _In_ ACCESS_MASK DesiredAccess,
                             _Out_ PHANDLE ProcessHandle);
