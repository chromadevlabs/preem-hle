#pragma once

#include <cstdio>       // printf
#include <optional>     // std::optional, std::make_optional
#include <cstdint>      // uint32_t etc

using std::nullopt;
using std::optional;
using std::make_optional;

#if WIN32
 #define BREAK()             __debugbreak()
#elif APPLE
 #define BREAK()             __builtin_trap()
#endif

#define stringify(value)    # value
#define concat(a, b)        a # b
#define check(expr, ...)    if (!bool(expr)) { printf("ASSERT - %s[%d]: ", __FILE__, __LINE__);    \
                                               printf(__VA_ARGS__); printf("\n"); fflush(stdout);  \
                                               BREAK(); }

template<typename RT, typename PT>
constexpr RT cast(PT pt) { return reinterpret_cast<RT>(pt); }

template<typename T>
constexpr T align(T value, T alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

template<typename T>
struct Range {
    constexpr Range()                 : Range(0, 0) {}
    constexpr Range(T _begin, T _end) : begin(_begin), end(_end) {}

    constexpr auto   length()        const { return end - begin; }
    constexpr auto contains(T value) const { return value >= begin && value < end; }
    constexpr auto    clamp(T value) const { return value <= begin ? begin : value >= end ? end : value; }
private:
    T begin, end;
};

template<typename T>
struct View {
    constexpr View()                    : View(nullptr, nullptr) {}
    constexpr View(T* _first, T* _last) : first(_first), last(_last) {}

    constexpr       auto  size() const { return cast<size_t>(last - first); }
    constexpr const auto begin() const { return first; }
    constexpr const auto   end() const { return last; }
    constexpr const auto  data() const { return first; }

    constexpr operator    auto() const { return size() > 0; }

private:
    T* first;
    T* last;
};

template<typename T>
constexpr auto make_view(T* _first, T* _last) {
    return View(_first, _last);
}

template<typename ContainerT>
constexpr auto make_view(const ContainerT& cont, size_t offset = 0, size_t len = 0) {
    len = len != 0 ? len : std::size(cont);
    return make_view(std::cbegin(cont) + offset, std::cbegin(cont) + offset + len);
}
