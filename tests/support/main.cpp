#include <cstring>

#include "check.hpp"

namespace check {
namespace {
int failures_in_current = 0;
} // namespace

std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

void fail(const char* file, int line, const char* expr) {
    ++failures_in_current;
    std::fprintf(stderr, "    %s:%d: CHECK(%s) failed\n", file, line, expr);
}

} // namespace check

int main(int argc, char** argv) {
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int passed = 0;
    int failed = 0;

    for (const auto& test : check::registry()) {
        if (filter != nullptr && std::strstr(test.name, filter) == nullptr) {
            continue;
        }
        check::failures_in_current = 0;
        test.fn();
        if (check::failures_in_current == 0) {
            ++passed;
        } else {
            ++failed;
            std::fprintf(stderr, "FAIL %s\n", test.name);
        }
    }

    std::printf("%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
