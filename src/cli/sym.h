/* Symbols routines header file. */
#pragma once

BOOL symInit();

BOOL symLoadImageSymbols(_In_ LPCWSTR lpFileName,
                         _In_ PVOID ImageBase,
                         _In_ ULONG ImageSize);

BOOL symLookupAddressBySymbol(_In_ LPCSTR SymbolName, _Out_ PULONG_PTR Address);
