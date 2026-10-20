#pragma once

// Tiny test harness so the host tests have no outside dependencies.

#include <cstdio>
#include <vector>

namespace check {

struct TestCase {
    const char* name;
    void (*fn)();
};

std::vector<TestCase>& registry();
void fail(const char* file, int line, const char* expr);

struct Registrar {
    Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

} // namespace check

#define TEST(name)                                                                                 \
    static void name();                                                                            \
    static const ::check::Registrar name##_registrar{#name, name};                                 \
    static void name()

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            ::check::fail(__FILE__, __LINE__, #expr);                                              \
        }                                                                                          \
    } while (0)

#define CHECK_EQ(a, b) CHECK((a) == (b))
