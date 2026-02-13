/* Razer Overlay Support driver interface header. */

#pragma once

//
// Razer Overlay Support driver interface for CVE-2017-9769.
//

#define RAZER_DEVICE_TYPE FILE_DEVICE_UNKNOWN

#define RAZER_OPEN_PROCESS_FUNCID   (DWORD)0x814

#define IOCTL_RZPNK_OPEN_PROCESS    \
    CTL_CODE(RAZER_DEVICE_TYPE, RAZER_OPEN_PROCESS_FUNCID, METHOD_BUFFERED, FILE_WRITE_ACCESS) //0x22A050

typedef struct _RAZER_OPEN_PROCESS {
    HANDLE ProcessId;
    HANDLE ProcessHandle;
} RAZER_OPEN_PROCESS, * PRAZER_OPEN_PROCESS;

BOOL WINAPI RazerOpenProcess(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle);
