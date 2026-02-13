/* Inter-process communication prototypes and definitions. */

#pragma once

#define KDU_PORT_NAME L"\\KduPort"

typedef struct _KDU_LPC_MESSAGE {
    PORT_MESSAGE64 Header;
    BYTE Data[128];
} KDU_LPC_MESSAGE, * PKDU_LPC_MESSAGE;

typedef struct _KDU_MSG {
    ULONG Function;
    NTSTATUS Status;
    ULONG64 Data;
    ULONG64 ReturnedLength;
} KDU_MSG, * PKDU_MSG;

VOID IpcSendHandleToServer(
    _In_ HANDLE ProcessHandle);
