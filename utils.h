#pragma once

#include <cstdio>       // printf
#include <optional>     // std::optional, std::make_optional
#include <cstdint>      // uint32_t etc
#include <string_view>  // std::string_view
#include <vector>

using std::optional;
using std::string_view;
using std::vector;
using std::byte;
using std::make_optional;

#if WIN32
 #define BREAK()             __debugbreak()
#else // we assume macos for now
 #define BREAK()             __builtin_trap()
#endif

#define stringify(value)    # value
#define concat(a, b)        a # b
#define check(expr, ...)    if (!bool(expr)) { printf("ASSERT - %s[%d]: ", __FILE__, __LINE__);    \
                                               printf(__VA_ARGS__); printf("\n"); fflush(stdout);  \
                                               BREAK(); }

template<typename RT, typename PT>
constexpr RT cast(PT pt) { return (RT)pt; }

template<typename T>
constexpr auto kb(T v) { return v * (T)1024; }

template<typename T>
constexpr auto mb(T v) { return kb(v) * (T)1024; }

template<typename T>
constexpr T align(T value, T alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

struct StringHash {
    constexpr StringHash() = default;
    constexpr StringHash(const char* string) : value(hash(string)) {}

    constexpr auto     empty() const { return value == 0; }
    constexpr operator  auto() const { return value; }

    static constexpr uint32_t hash(const char* str, uint32_t seed = 2166136261u) {
        return (*str == '\0') ? seed : hash(str + 1, (seed ^ *str) * 16777619u);
    }

private:
    uint32_t value = 0;
};

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

    constexpr       auto   size() const { return cast<size_t>(last - first); }
    constexpr const auto  begin() const { return first; }
    constexpr const auto    end() const { return last; }
    constexpr const auto   data() const { return first; }
    constexpr operator     auto() const { return size() > 0; }

    constexpr auto operator[](size_t index) const { return first[index]; }

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


optional<vector<uint8_t>> file_load(const string_view& path);
bool file_save(const string_view& path, const vector<uint8_t>& data);