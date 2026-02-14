# ASRock 驱动程序漏洞利用模块

## 概述

该模块实现了针对多个 ASRock 主板驱动程序的漏洞利用，允许从用户态进行任意物理内存读写操作。这些驱动程序由于未正确验证输入缓冲区，导致存在 CVE-2020-15368 漏洞。

## 支持的目标驱动程序

| 名称 | 设备路径 | 服务名 | 描述 |
|------|----------|--------|------|
| asrock | \\.\AsrDrv106 | AsrDrv106 | ASRock IO Driver (AsrDrv106) |
| asrock2 | \\.\AxtuDrv | AxtuDrv | ASRock Axtu Driver (AxtuDrv) |
| asrock3 | \\.\AppShopDrv103 | AppShopDrv103 | ASRock AppShop Driver (AppShopDrv103) |
| asrock4 | \\.\AsrDrv107n | AsrDrv107n | ASRock IO Driver (AsrDrv107n) |
| asrock5 | \\.\AsrDrv107 | AsrDrv107 | ASRock IO Driver (AsrDrv107) |

## 漏洞原理

### 核心漏洞代码分析

驱动程序在处理 IOCTL 0xB00（EXEC_DISPATCH）时，存在一个物理内存映射和拷贝操作：

```assembly
000114d0  if (r8_1 == 0x22e808)           ; IOCTL
000115ee  BaseAddress_1 = MmMapIoSpace(..., MmNonCached)  ; 映射物理内存
000115fa  if (BaseAddress_1 != 0)
00011603      rdx_12 = *(uint64_t*)(AssociatedIrp + 0x10)  ; 目标缓冲区
00011607      i_1 = AssociatedIrp[2]                       ; 要拷贝的大小
0001160a      BaseAddress_3 = BaseAddress_1                ; 源地址（物理内存）
          
00011654      while (i_1 != 0)                             ; 循环拷贝
0001160f          rax_18 = AssociatedIrp[3]                ; 粒度控制
00011615          if (rax_18 == 0)                         ; 字节粒度
00011645              rax_18 = *(uint8_t*)BaseAddress_3
00011647              BaseAddress_3 += 1
0001164a              *(uint8_t*)rdx_12 = rax_18
0001164c              rdx_12 += 1
0001164f              i_1 -= 1
                  
0001161a          else if (rax_18 == 1)                    ; 字粒度（2字节）
00011632              rax_21 = *(uint16_t*)BaseAddress_3
00011635              BaseAddress_3 += 2
00011639              *(uint16_t*)rdx_12 = rax_21
0001163c              rdx_12 += 2
00011640              i_1 -= 2
                  
0001161f          else if (rax_18 == 2)                    ; 双字粒度（4字节）
00011621              rax_20 = *(uint32_t*)BaseAddress_3
00011623              BaseAddress_3 += 4
00011627              *(uint32_t*)rdx_12 = rax_20
00011629              rdx_12 += 4
0001162d              i_1 -= 4
```

### 漏洞关键点

1. **物理内存映射**：驱动程序使用 `MmMapIoSpace` 将任意物理地址映射到内核空间，没有对物理地址范围进行合法性检查

2. **缺乏权限验证**：未验证调用者是否有权限访问指定的物理内存区域

3. **用户态缓冲区操作**：直接将物理内存内容拷贝到用户态提供的缓冲区

由于 `MmMapIoSpace` 在 Win10 1809 后不再能访问 PML4，此类漏洞无法进行物理地址到虚拟地址的转换