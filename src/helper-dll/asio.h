/* ASUS hack-o-rama prototypes and definitions. */

#pragma once

#define FILE_DEVICE_ASUSIO (DWORD)0x0000A040

#define ASUSIO3_REGISTER_FUNCID (DWORD)0x924

#define IOCTL_ASUSIO_REGISTER_TRUSTED_CALLER                               \
    CTL_CODE(FILE_DEVICE_ASUSIO, ASUSIO3_REGISTER_FUNCID, METHOD_BUFFERED, \
             FILE_WRITE_ACCESS)  // 0xA040A490

VOID RegisterTrustedCallerForAsIO();
