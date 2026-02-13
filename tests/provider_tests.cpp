/* Provider correctness tests - CLI wrapper */

#include <windows.h>
#include <print>
#include <string>
#include "test-lib/provider_tester.h"
#include "core/kdu_core.h"

using namespace kdu;
using namespace kdu::testing;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::println("Usage: provider-tests <provider_name> [--judge-provider=<name>]");
        std::println("\nRegistered providers:");
        
        auto& manager = core::DriverManager::instance();
        auto all = manager.get_all_providers();
        for (const auto& p : all) {
            std::println("  - {}", p->metadata().driver_name);
        }
        
        return 1;
    }
    
    std::string provider_name = argv[1];
    std::string judge_provider;
    
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg.starts_with("--judge-provider=")) {
            judge_provider = arg.substr(17);
        }
    }
    
    std::println("Testing provider: {}", provider_name);
    if (!judge_provider.empty()) {
        std::println("Judge provider: {}", judge_provider);
    }
    std::println("");
    
    ProviderTester tester(provider_name, judge_provider);
    auto results = tester.run_all_tests();
    
    print_test_results(results);
    
    auto summary = summarize_results(results);
    return summary.failed > 0 ? 1 : 0;
}
