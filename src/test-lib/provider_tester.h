/* Provider test library - can be used by CLI and unit tests */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include "core/kdu_core.h"

namespace kdu::testing {

struct TestResult {
    std::string test_name;
    bool passed;
    std::string error_message;
    std::string details;
};

class ProviderTester {
public:
    explicit ProviderTester(const std::string& provider_name, 
                           const std::string& judge_provider = "");
    
    // 运行所有测试
    std::vector<TestResult> run_all_tests();
    
    // 单独运行各个测试
    TestResult test_create_instance();
    TestResult test_physical_memory_read();
    TestResult test_virtual_memory_read();
    TestResult test_virtual_to_physical();
    TestResult test_physical_memory_write_back();
    TestResult test_query_pml4();
    TestResult test_compare_with_judge();
    
private:
    std::string provider_name_;
    std::string judge_provider_name_;
    std::unique_ptr<core::DriverExploit> driver_;
    std::unique_ptr<core::DriverExploit> judge_driver_;
    
    // 尝试获取有效的物理地址进行测试
    std::expected<uintptr_t, std::string> get_test_physical_address();
};

// 打印测试结果
void print_test_results(const std::vector<TestResult>& results);

// 获取通过/失败数量
struct TestSummary {
    int passed;
    int failed;
    int total;
};

TestSummary summarize_results(const std::vector<TestResult>& results);

}  // namespace kdu::testing
