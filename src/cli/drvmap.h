/* Prototypes and definitions for driver mapping. */
#pragma once

PVOID KDUSetupShellCode(_In_ PKDU_CONTEXT Context,
                        _In_ PVOID ImageBase,
                        _Out_ PHANDLE SectionHandle);

VOID KDUShowPayloadResult(_In_ PKDU_CONTEXT Context, _In_ HANDLE SectionHandle);

BOOL KDUMapDriver(_In_ PKDU_CONTEXT Context, _In_ PVOID ImageBase);

BOOL WINAPI KDUPagePatchCallback(_In_ ULONG_PTR Address,
                                 _In_ PVOID UserContext);
