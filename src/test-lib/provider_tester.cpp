#include "provider_tester.h"
#include <print>
#include <cstring>
#include <format>

namespace kdu::testing {

constexpr uintptr_t KUSER_SHARED_DATA_VA = 0xFFFFF78000000000;
constexpr size_t OFFSET_NT_MAJOR_VERSION = 0x260;
constexpr size_t OFFSET_TICK_COUNT_LOW = 0x0;

ProviderTester::ProviderTester(const std::string& provider_name,
                               const std::string& judge_provider)
    : provider_name_(provider_name), judge_provider_name_(judge_provider) {}

std::vector<TestResult> ProviderTester::run_all_tests() {
    std::vector<TestResult> results;

    results.push_back(test_create_instance());
    if (!results.back().passed)
        return results;

    if (!judge_provider_name_.empty()) {
        auto judge = core::DriverManager::instance().find_provider_by_name(
            judge_provider_name_);
        if (judge) {
            auto judge_result = judge->create_instance();
            if (judge_result) {
                judge_driver_ = std::move(*judge_result);
                std::println("Using judge provider: {}", judge_provider_name_);
            }
        }
    }

    results.push_back(test_virtual_to_physical());
    results.push_back(test_physical_memory_read());
    results.push_back(test_virtual_memory_read());
    results.push_back(test_query_pml4());
    results.push_back(test_physical_memory_write_back());

    if (judge_driver_) {
        results.push_back(test_compare_with_judge());
    }

    return results;
}

TestResult ProviderTester::test_create_instance() {
    auto provider =
        core::DriverManager::instance().find_provider_by_name(provider_name_);
    if (!provider) {
        return {"Create Instance", false, "Provider not found", ""};
    }

    auto driver_result = provider->create_instance();
    if (!driver_result) {
        return {"Create Instance", false, driver_result.error(), ""};
    }

    driver_ = std::move(*driver_result);
    return {"Create Instance", true, "", ""};
}

std::expected<uintptr_t, std::string>
ProviderTester::get_test_physical_address() {
    auto* translator = driver_->as<core::IVirtualToPhysical>();
    if (translator) {
        auto pa = translator->try_virtual_to_physical(KUSER_SHARED_DATA_VA);
        if (pa)
            return *pa;
    }

    if (judge_driver_) {
        auto* judge_translator = judge_driver_->as<core::IVirtualToPhysical>();
        if (judge_translator) {
            auto pa = judge_translator->try_virtual_to_physical(
                KUSER_SHARED_DATA_VA);
            if (pa)
                return *pa;
        }
    }

    return 0x1000;
}

TestResult ProviderTester::test_physical_memory_read() {
    auto* reader = driver_->as<core::IPhysicalMemoryRead>();
    if (!reader)
        return {"Physical Memory Read", false, "Interface not supported", ""};

    auto pa_result = get_test_physical_address();
    if (!pa_result)
        return {"Physical Memory Read", false, "Address error",
                pa_result.error()};

    uintptr_t test_pa = *pa_result;
    auto result = reader->try_read_physical_memory(test_pa, 0x1000);
    if (!result)
        return {"Physical Memory Read", false, result.error(), ""};

    if (test_pa != 0x1000 && result->size() > OFFSET_NT_MAJOR_VERSION + 4) {
        uint32_t nt_ver = *reinterpret_cast<const uint32_t*>(result->data() + OFFSET_NT_MAJOR_VERSION);
        if (nt_ver >= 10000 && nt_ver <= 100000) {
            return {"Physical Memory Read", true, "",
                    std::format("PA: 0x{:016X} (Verified NT Version: {})",
                                test_pa, nt_ver)};
        } else {
            return {"Physical Memory Read", false,
                    std::format(
                        "PA: 0x{:016X} (Unverified, suspicious NT version: {})",
                        test_pa, nt_ver),
                    ""};
        }
    }

    return {"Physical Memory Read", true, "",
            std::format("PA: 0x{:016X} (Unverified)", test_pa)};
}

TestResult ProviderTester::test_virtual_memory_read() {
    auto* reader = driver_->as<core::IVirtualMemoryRead>();
    if (!reader)
        return {"Virtual Memory Read", false, "Interface not supported", ""};

    auto result = reader->try_read_virtual_memory(KUSER_SHARED_DATA_VA, 0x1000);
    if (!result)
        return {"Virtual Memory Read", false, result.error(), ""};

    uint32_t nt_ver = *reinterpret_cast<const uint32_t*>(
        result->data() + OFFSET_NT_MAJOR_VERSION);
    if (nt_ver >= 10000 && nt_ver <= 100000) {
        return {
            "Virtual Memory Read", true, "",
            std::format("Read from KUSER_SHARED_DATA succeeded, NT Version: {}",
                        nt_ver)};
    } else {
        return {"Virtual Memory Read", false,
                std::format("Read from KUSER_SHARED_DATA succeeded but NT "
                            "version looks suspicious: {}",
                            nt_ver),
                ""};
    }
}

TestResult ProviderTester::test_virtual_to_physical() {
    auto* translator = driver_->as<core::IVirtualToPhysical>();
    if (!translator)
        return {"Virtual to Physical", false, "Interface not supported", ""};

    auto result = translator->try_virtual_to_physical(KUSER_SHARED_DATA_VA);
    if (!result)
        return {"Virtual to Physical", false, result.error(), ""};

    if (*result == 0 || (*result & 0xFFF) != 0) {
        return {"Virtual to Physical", false,
                std::format("Alignment error: 0x{:016X}", *result), ""};
    }

    return {"Virtual to Physical", true, "",
            std::format("VA: 0x{:016X} -> PA: 0x{:016X}", KUSER_SHARED_DATA_VA,
                        *result)};
}

TestResult ProviderTester::test_query_pml4() {
    auto* pml4_query = driver_->as<core::IQueryPML4>();
    if (!pml4_query)
        return {"Query PML4", false, "Interface not supported", ""};

    auto result = pml4_query->try_query_pml4();
    if (!result)
        return {"Query PML4", false, result.error(), ""};

    return {"Query PML4", true, "",
            std::format("CR3/PML4: 0x{:016X}", *result)};
}

TestResult ProviderTester::test_physical_memory_write_back() {
    auto* translator = driver_->as<core::IVirtualToPhysical>();
    auto* writer = driver_->as<core::IPhysicalMemoryWrite>();
    auto* reader = driver_->as<core::IPhysicalMemoryRead>();

    if (!translator || !writer || !reader) {
        return {"Physical Memory Write", false,
                "Required interfaces (VA2PA, ReadPA, WritePA) not supported",
                ""};
    }

    auto pa_res = translator->try_virtual_to_physical(KUSER_SHARED_DATA_VA +
                                                      OFFSET_TICK_COUNT_LOW);
    if (!pa_res)
        return {"Physical Memory Write", false, "Failed to resolve PA",
                pa_res.error()};
    uintptr_t target_pa = *pa_res;

    auto original_data = reader->try_read_physical_memory(target_pa, 4);
    if (!original_data)
        return {"Physical Memory Write", false, "Failed to read original",
                original_data.error()};
    uint32_t original_val =
        *reinterpret_cast<const uint32_t*>(original_data->data());

    uint32_t test_val = 0x114514;

    auto write_res = writer->try_write_physical_memory(target_pa, &test_val, 4);
    if (!write_res)
        return {"Physical Memory Write", false, write_res.error(), ""};

    auto verify_data = reader->try_read_physical_memory(target_pa, 4);
    if (!verify_data)
        return {"Physical Memory Write", false, "Failed to read back",
                verify_data.error()};
    uint32_t verify_val =
        *reinterpret_cast<const uint32_t*>(verify_data->data());
    std::ignore =
        writer->try_write_physical_memory(target_pa, &original_val, 4);
    if (verify_val != test_val) {
        return {"Physical Memory Write", false,
                std::format(
                    "Verification failed: wrote 0x{:08X}, read back 0x{:08X}",
                    test_val, verify_val),
                ""};
    }

    return {"Physical Memory Write", true, "",
            std::format("Successfully wrote 0x{:08X} to PA 0x{:016X}", test_val,
                        target_pa)};
}

TestResult ProviderTester::test_compare_with_judge() {
    auto* reader = driver_->as<core::IPhysicalMemoryRead>();
    auto* judge_reader = judge_driver_->as<core::IPhysicalMemoryRead>();

    if (!reader || !judge_reader)
        return {"Compare with Judge", false, "Interface mismatch", ""};

    auto pa_result = get_test_physical_address();
    if (!pa_result)
        return {"Compare with Judge", false, "No test address", ""};

    uintptr_t base_pa = *pa_result;
    std::vector<uintptr_t> offsets = {0, 0x100, OFFSET_NT_MAJOR_VERSION};

    for (auto off : offsets) {
        auto r1 = reader->try_read_physical_memory(base_pa + off, 8);
        auto r2 = judge_reader->try_read_physical_memory(base_pa + off, 8);
        if (r1 && r2 && *r1 != *r2) {
            return {"Compare with Judge", false,
                    std::format("Mismatch at 0x{:016X}", base_pa + off), ""};
        }
    }

    return {"Compare with Judge", true, "",
            "Values matched with judge provider"};
}

void print_test_results(const std::vector<TestResult>& results) {
    std::println("\n{:^50}", "=== KDU PROVIDER TEST REPORT ===");
    std::println("{:-^50}", "");

    for (const auto& res : results) {
        std::string status = res.passed ? "[ PASS ]" : "[ FAIL ]";
        std::println("{:<10} {:<25}", status, res.test_name);
        if (!res.details.empty())
            std::println("           info:  {}", res.details);
        if (!res.error_message.empty())
            std::println("           error: {}", res.error_message);
    }

    auto summary = summarize_results(results);
    std::println("{:-^50}", "");
    std::println("Summary: {} Passed, {} Failed, {} Total", summary.passed,
                 summary.failed, summary.total);
}

TestSummary summarize_results(const std::vector<TestResult>& results) {
    TestSummary s{0, 0, 0};
    for (const auto& r : results) {
        s.total++;
        r.passed ? s.passed++ : s.failed++;
    }
    return s;
}

}  // namespace kdu::testing