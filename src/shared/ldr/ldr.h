/* Common header file for PE loader unit. */

#pragma once

LPVOID PELoaderLoadImage(_In_ LPVOID Buffer, _Out_opt_ PDWORD SizeOfImage);

LPVOID PELoaderGetProcAddress(_In_ LPVOID ImageBase, _In_ PCHAR RoutineName);
