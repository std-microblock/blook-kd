# Provider 开发指南

本文档介绍如何为 KDU Core 框架编写新的驱动 Provider，以及如何从旧版本迁移现有 Provider。

## 目录

- [快速开始](#快速开始)
- [Provider 架构概述](#provider-架构概述)
- [编写新 Provider](#编写新-provider)
- [从旧版本迁移](#从旧版本迁移)
- [测试 Provider](#测试-provider)
- [最佳实践](#最佳实践)

## 快速开始

一个最小的 Provider 实现包含三个部分：

1. **驱动 Exploit 类** - 实现具体的驱动交互逻辑
2. **Provider 类** - 工厂类，负责创建 Exploit 实例
3. **自动注册** - 使用 `ProviderRegistrar` 自动注册

### 最小示例

```cpp
// mydriver.cpp
#include "core/kdu_core.h"

// 1. 定义 Exploit 类
class MyDriverExploit : public core::DriverExploit,
                        public core::IPhysicalMemoryRead {
public:
    explicit MyDriverExploit(HANDLE device_handle) 
        : DriverExploit(device_handle, L"mydrv") {}
    
    std::expected<std::vector<uint8_t>, std::string>
    try_read_physical_memory(uintptr_t addr, size_t size) const noexcept override {
        // 实现物理内存读取
        std::vector<uint8_t> buffer(size);
        // ... IOCTL 调用 ...
        return buffer;
    }
};

// 2. 定义 Provider 类
class MyDriverProvider : public core::IDriverProvider {
public:
    MyDriverProvider() {
        metadata_.driver_name = "mydrv";
        metadata_.device_name = "\\\\.\\MyDevice";
        metadata_.service_name = "mydrv";
        metadata_.description = "My Driver Description";
        metadata_.cve_id = "CVE-XXXX-XXXXX";
        metadata_.driver_data = _binary_mydriver_bin_start;
        metadata_.driver_size = _binary_mydriver_bin_end - _binary_mydriver_bin_start;
        metadata_.capabilities = core::AbilityFlags::PhysicalMemoryRead;
    }
    
    std::expected<void, std::string> check_available() const noexcept override {
        return {}; // 简单实现：总是可用
    }
    
    std::expected<std::unique_ptr<core::DriverExploit>, std::string>
    create_instance() noexcept override {
        auto result = load_driver_from_memory(
            metadata_.driver_data,
            metadata_.driver_size,
            std::wstring(metadata_.service_name.begin(), metadata_.service_name.end()),
            std::wstring(metadata_.device_name.begin(), metadata_.device_name.end())
        );
        
        if (!result) return std::unexpected(result.error());
        return std::make_unique<MyDriverExploit>(*result);
    }
};

// 3. 自动注册
extern "C" const uint8_t _binary_mydriver_bin_start[];
extern "C" const uint8_t _binary_mydriver_bin_end[];

static core::ProviderRegistrar<MyDriverProvider> reg;
```

## Provider 架构概述

### 核心组件

```
┌─────────────────────────────────────┐
│      DriverManager (Singleton)      │
│  - 管理所有已注册的 Provider        │
│  - 根据 Capability 匹配驱动         │
└─────────────────────────────────────┘
               ▲
               │ 注册
               │
┌──────────────┴─────────────────────┐
│   IDriverProvider (工厂接口)       │
│  - metadata_: DriverMetadata       │
│  - check_available()               │
│  - create_instance()               │
│  - load_driver_from_memory()       │
│  - unload_driver()                 │
└────────────────────────────────────┘
               │ 创建
               ▼
┌────────────────────────────────────┐
│      DriverExploit (基类)          │
│  - device_handle_: HANDLE          │
│  - service_name_: wstring          │
│  - try_unload()                    │
│  - as<Interface>()                 │
└────────────────────────────────────┘
               │ 继承
               ▼
┌────────────────────────────────────┐
│   具体驱动类 (如 GdrvExploit)      │
│  + IPhysicalMemoryRead             │
│  + IPhysicalMemoryWrite            │
│  + IVirtualToPhysical              │
│  + ...                             │
└────────────────────────────────────┘
```

### 能力标志 (AbilityFlags)

使用位标志表示驱动支持的功能：

```cpp
enum class AbilityFlags : uint64_t {
    PhysicalMemoryRead      = 1ULL << 0,
    PhysicalMemoryWrite     = 1ULL << 1,
    VirtualMemoryRead       = 1ULL << 2,
    VirtualMemoryWrite      = 1ULL << 3,
    VirtualToPhysical       = 1ULL << 4,
    QueryPML4               = 1ULL << 5,
    ReadMSR                 = 1ULL << 6,
    WriteMSR                = 1ULL << 7,
    // ... 更多能力
};
```

### 接口隔离

每个能力对应一个独立接口：

```cpp
class IPhysicalMemoryRead {
public:
    virtual std::expected<std::vector<uint8_t>, std::string>
    try_read_physical_memory(uintptr_t address, size_t size) const noexcept = 0;
};

class IPhysicalMemoryWrite {
public:
    virtual std::expected<void, std::string>
    try_write_physical_memory(uintptr_t address, const void* data, size_t size) noexcept = 0;
};
```

## 编写新 Provider

### 步骤 1: 分析驱动能力

首先确定驱动支持哪些操作：

- 查看驱动的 IOCTL 代码
- 分析驱动的功能（物理内存访问、MSR 访问等）
- 确定需要实现的接口

### 步骤 2: 创建目录结构

```
src/drivers/mydriver/
├── mydriver.cpp          # 主实现文件
└── data/
    └── README.md         # 说明如何获取驱动二进制
```

### 步骤 3: 实现 Exploit 类

```cpp
class MyDriverExploit : public core::DriverExploit,
                        public core::IPhysicalMemoryRead,
                        public core::IPhysicalMemoryWrite {
public:
    explicit MyDriverExploit(HANDLE device_handle) 
        : DriverExploit(device_handle, L"mydrv") {}
    
    // 实现物理内存读取
    std::expected<std::vector<uint8_t>, std::string>
    try_read_physical_memory(uintptr_t address, size_t size) const noexcept override {
        try {
            std::vector<uint8_t> buffer(size);
            
            // 设置 IOCTL 请求结构
            MY_IOCTL_STRUCTURE request{};
            request.PhysicalAddress = address;
            request.Length = size;
            
            // 调用 DeviceIoControl
            DWORD bytes_returned = 0;
            BOOL success = DeviceIoControl(
                device_handle_,
                IOCTL_MY_READ_PHYSICAL_MEMORY,
                &request, sizeof(request),
                buffer.data(), static_cast<DWORD>(size),
                &bytes_returned,
                nullptr
            );
            
            if (!success) {
                return std::unexpected("IOCTL failed");
            }
            
            return buffer;
        } catch (...) {
            return std::unexpected("Exception in read_physical_memory");
        }
    }
    
    // 实现物理内存写入
    std::expected<void, std::string>
    try_write_physical_memory(uintptr_t address, const void* data, size_t size) noexcept override {
        // 类似实现...
    }
};
```

### 步骤 4: 实现 Provider 类

```cpp
class MyDriverProvider : public core::IDriverProvider {
public:
    MyDriverProvider() {
        // 设置元数据
        metadata_.driver_name = "mydrv";
        metadata_.device_name = "\\\\.\\MyDevice";
        metadata_.service_name = "mydrv_service";
        metadata_.description = "My Vulnerable Driver (CVE-XXXX-XXXXX)";
        metadata_.cve_id = "CVE-XXXX-XXXXX";
        
        // 设置嵌入的驱动二进制
        metadata_.driver_data = _binary_mydriver_bin_start;
        metadata_.driver_size = _binary_mydriver_bin_end - _binary_mydriver_bin_start;
        
        // 设置能力标志
        metadata_.capabilities = 
            core::AbilityFlags::PhysicalMemoryRead |
            core::AbilityFlags::PhysicalMemoryWrite;
    }
    
    std::expected<void, std::string> check_available() const noexcept override {
        // 可选：检查系统版本、处理器架构等
        
        // 检查驱动是否已加载
        HANDLE hDevice = CreateFileW(
            std::wstring(metadata_.device_name.begin(), metadata_.device_name.end()).c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            return {}; // 已加载
        }
        
        // 检查驱动二进制是否有效
        if (!metadata_.driver_data || metadata_.driver_size == 0) {
            return std::unexpected("Driver binary not embedded");
        }
        
        return {};
    }
    
    std::expected<std::unique_ptr<core::DriverExploit>, std::string>
    create_instance() noexcept override {
        // 使用工具函数加载驱动
        std::wstring service_name(metadata_.service_name.begin(), 
                                 metadata_.service_name.end());
        std::wstring device_name(metadata_.device_name.begin(), 
                                metadata_.device_name.end());
        
        auto result = load_driver_from_memory(
            metadata_.driver_data,
            metadata_.driver_size,
            service_name,
            device_name
        );
        
        if (!result) {
            return std::unexpected(result.error());
        }
        
        return std::make_unique<MyDriverExploit>(*result);
    }
};
```

### 步骤 5: 添加驱动二进制

将驱动二进制文件放置到 `src/victim-drivers/drv/mydriver.bin`。

### 步骤 6: 更新 xmake.lua

```lua
target("mydriver")
    set_kind("static")
    set_encodings("utf-8")
    add_defines("UNICODE")
    add_rules("utils.bin2obj", {extensions = {".bin"}})
    add_files("src/drivers/mydriver/**.cpp")
    add_files("src/victim-drivers/drv/mydriver.bin")
    add_headerfiles("src/drivers/mydriver/**.h")
    add_includedirs("src", {public = true})
    add_deps("core")
```

### 步骤 7: 注册 Provider

```cpp
// 在文件末尾
extern "C" {
    extern const uint8_t _binary_mydriver_bin_start[];
    extern const uint8_t _binary_mydriver_bin_end[];
}

namespace kdu::drivers::mydriver {
    static core::ProviderRegistrar<MyDriverProvider> reg;
}
```

## 从旧版本迁移

旧版本使用 `kduplist.h` 中的硬编码函数指针数组。迁移步骤：

### 步骤 1: 识别驱动函数

在 `src/cli/idrv/` 目录找到对应的驱动实现文件，例如 `mapmem.cpp` (GDRV 驱动)。

旧代码结构：
```cpp
// kduplist.h
KDU_PROVIDER g_KDUProviders[] = {
    {
        IDR_GDRV,
        KDU_PROVIDER_GIBABYTE_GDRV,
        KDU_MAX_NTBUILDNUMBER,
        KDU_MIN_NTBUILDNUMBER,
        L"GDRV",
        L"CVE-2018-19320",
        L"Giga-Byte Technology GDRV, ATSZIO, GLCKIO, ENETECHIO",
        SourceBaseNone,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        (LPWSTR)GDRV_DEVICE_NAME,
        KDUPROV_SC_NONE,
        (provQueryPML4)GioQueryPML4Value,
        (provReadKernelVM)GioVirtualToPhysical,
        (provWriteKernelVM)GioWriteKernelVirtualMemory,
        ...
    }
};
```

### 步骤 2: 提取 IOCTL 定义

从旧的头文件（如 `mapmem.h`）复制 IOCTL 定义和结构：

```cpp
#define IOCTL_GDRV_MAP_USER_PHYSICAL_MEMORY \
    CTL_CODE(GDRV_DEVICE_TYPE, GRV_IOCTL_INDEX + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _MAPMEM_PHYSICAL_MEMORY_INFO {
    ULONG InterfaceType;
    ULONG BusNumber;
    LARGE_INTEGER BusAddress;
    ULONG AddressSpace;
    ULONG Length;
} MAPMEM_PHYSICAL_MEMORY_INFO;
```

### 步骤 3: 识别功能函数

旧代码中的函数指针对应新接口：

| 旧函数指针 | 新接口 |
|-----------|--------|
| `provReadPhysicalMemory` | `IPhysicalMemoryRead` |
| `provWritePhysicalMemory` | `IPhysicalMemoryWrite` |
| `provReadKernelVM` | `IVirtualMemoryRead` |
| `provWriteKernelVM` | `IVirtualMemoryWrite` |
| `provVirtualToPhysical` | `IVirtualToPhysical` |
| `provQueryPML4` | `IQueryPML4` |
| `provReadMSR` | `IReadMSR` |
| `provWriteMSR` | `IWriteMSR` |

### 步骤 4: 转换实现

**旧代码** (`mapmem.cpp`):
```cpp
BOOL WINAPI GioReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    MAPMEM_PHYSICAL_MEMORY_INFO request;
    PVOID pMapSection = nullptr;
    // ... 实现 ...
    return TRUE;
}
```

**新代码**:
```cpp
std::expected<std::vector<uint8_t>, std::string>
GdrvExploit::try_read_physical_memory(uintptr_t address, size_t size) const noexcept override {
    try {
        std::vector<uint8_t> buffer(size);
        MAPMEM_PHYSICAL_MEMORY_INFO request{};
        PVOID pMapSection = nullptr;
        // ... 相同的逻辑 ...
        return buffer;
    } catch (...) {
        return std::unexpected("Exception in read_physical_memory");
    }
}
```

### 步骤 5: 处理特殊情况

#### 需要 PML4 的驱动

旧标志：`KDUPROV_FLAGS_PML4_FROM_LOWSTUB`

新实现：实现 `IQueryPML4` 接口。

#### 虚拟内存通过物理内存实现

如果驱动不直接支持虚拟内存读写，通过 `IVirtualToPhysical` + 物理内存接口实现：

```cpp
std::expected<std::vector<uint8_t>, std::string>
try_read_virtual_memory(uintptr_t virtual_address, size_t size) const noexcept override {
    auto phys = try_virtual_to_physical(virtual_address);
    if (!phys) return std::unexpected(phys.error());
    return try_read_physical_memory(*phys, size);
}
```

### 步骤 6: 迁移元数据

```cpp
// 旧的 kduplist.h 中的信息
{
    IDR_GDRV,                    // 资源 ID
    KDU_PROVIDER_GIBABYTE_GDRV,  // Provider ID
    KDU_MAX_NTBUILDNUMBER,       // 最大 NT 版本
    KDU_MIN_NTBUILDNUMBER,       // 最小 NT 版本
    L"GDRV",                     // 名称
    L"CVE-2018-19320",           // CVE
    L"Giga-Byte...",             // 描述
    ...
}

// 新的 metadata_
metadata_.driver_name = "gdrv";
metadata_.device_name = "\\\\.\\GIO";
metadata_.service_name = "gdrv";
metadata_.description = "Gigabyte GDRV (CVE-2018-19320)";
metadata_.cve_id = "CVE-2018-19320";
metadata_.driver_data = _binary_gdrv_bin_start;
metadata_.driver_size = _binary_gdrv_bin_end - _binary_gdrv_bin_start;
metadata_.capabilities = 
    AbilityFlags::PhysicalMemoryRead |
    AbilityFlags::PhysicalMemoryWrite |
    AbilityFlags::VirtualMemoryRead |
    AbilityFlags::VirtualMemoryWrite |
    AbilityFlags::VirtualToPhysical |
    AbilityFlags::QueryPML4;
```

### 完整迁移示例

参考 `src/drivers/gdrv-exploit/gdrv_exploit.cpp`，这是从旧版 `mapmem.cpp` 迁移的完整示例。

## 测试 Provider

### 单元测试

创建测试文件 `tests/test_mydriver.cpp`：

```cpp
#include <gtest/gtest.h>
#include "core/kdu_core.h"

TEST(MyDriverTest, ReadSharedUserData) {
    auto& manager = core::DriverManager::instance();
    auto provider = manager.find_provider_by_name("mydrv");
    ASSERT_NE(provider, nullptr);
    
    auto driver = provider->create_instance();
    ASSERT_TRUE(driver.has_value());
    
    auto* reader = (*driver)->as<core::IPhysicalMemoryRead>();
    ASSERT_NE(reader, nullptr);
    
    // 读取 KUSER_SHARED_DATA
    constexpr uintptr_t KUSER_SHARED_DATA = 0xFFFFF78000000000;
    auto result = reader->try_read_physical_memory(KUSER_SHARED_DATA, 16);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 16);
}
```

### 手动测试

使用 `cli-new` 进行测试：

```bash
# 列出驱动
xmake r cli-new --list

# 读取物理内存
xmake r cli-new --read-phys 0x1000 -s 16 -d mydrv

# 运行完整测试
xmake r cli-new --test -d mydrv
```

## 最佳实践

### 1. 错误处理

始终使用 `std::expected<T, std::string>` 返回详细错误信息：

```cpp
if (!DeviceIoControl(...)) {
    DWORD error = GetLastError();
    return std::unexpected("IOCTL failed: " + std::to_string(error));
}
```

### 2. 异常安全

所有 `noexcept` 函数必须捕获异常：

```cpp
std::expected<...> try_read(...) const noexcept override {
    try {
        // 实现
    } catch (const std::exception& e) {
        return std::unexpected(std::string("Exception: ") + e.what());
    } catch (...) {
        return std::unexpected("Unknown exception");
    }
}
```

### 3. 资源管理

- 设备句柄由 `DriverExploit` 基类自动管理
- 使用 RAII 管理映射内存等资源
- 在 `create_instance` 失败时清理资源

```cpp
auto result = load_driver_from_memory(...);
if (!result) {
    // load_driver_from_memory 已经清理了资源
    return std::unexpected(result.error());
}
```

### 4. 单一职责

每个接口实现一个功能：

```cpp
// ✓ 好
class MyExploit : public IPhysicalMemoryRead, public IPhysicalMemoryWrite { ... }

// ✗ 不好 - 在一个函数中实现多个功能
```

### 5. 文档注释

为复杂逻辑添加注释：

```cpp
// GDRV 驱动会将物理地址截断为 32 位，不能用于 >4GB 的地址
// 参考：CVE-2018-19320 分析报告
auto physical_addr = request.Address.LowPart;  // 只取低 32 位
```

### 6. 命名规范

- Provider 类: `<DriverName>Provider`
- Exploit 类: `<DriverName>Exploit`
- 命名空间: `kdu::drivers::<driver_name>`

### 7. 编译时检查

使用 `static_assert` 验证结构大小：

```cpp
#pragma pack(push, 1)
struct MY_IOCTL_REQUEST {
    ULONG64 Address;
    ULONG Size;
};
#pragma pack(pop)

static_assert(sizeof(MY_IOCTL_REQUEST) == 12, "Structure size mismatch");
```

## 常见问题

### Q: 驱动加载失败怎么办？

A: 检查以下几点：
1. 是否以管理员权限运行
2. 驱动文件是否正确嵌入（检查 bin2obj 符号）
3. 设备名称是否正确
4. 查看 `load_driver_from_memory` 返回的错误信息

### Q: 如何调试 IOCTL 调用？

A: 
1. 使用 WinDbg 附加到内核
2. 打印 IOCTL 请求和响应的十六进制数据
3. 对比旧版本的实现

### Q: 如何处理不同 Windows 版本？

A: 在 `check_available()` 中检查版本：

```cpp
std::expected<void, std::string> check_available() const noexcept override {
    RTL_OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    RtlGetVersion(&version);
    
    if (version.dwBuildNumber < 7600) {
        return std::unexpected("Requires Windows 7 or later");
    }
    
    return {};
}
```

### Q: 如何支持多个设备名称？

A: 在 `create_instance()` 中尝试多个设备名称：

```cpp
const wchar_t* device_names[] = { L"\\\\.\\Device1", L"\\\\.\\Device2" };
for (auto name : device_names) {
    auto result = load_driver_from_memory(..., name);
    if (result) return std::make_unique<MyExploit>(*result);
}
return std::unexpected("Failed to open any device");
```

## 参考资料

- [KDU Core API 文档](./API.md)
- [接口定义](../src/core/interfaces/)
- [GDRV 迁移示例](../src/drivers/gdrv-exploit/gdrv_exploit.cpp)
- [测试框架](../tests/)

---

**需要帮助？** 在 GitHub Issues 中提问或查看现有的 Provider 实现作为参考。
