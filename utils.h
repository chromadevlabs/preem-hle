#pragma once

#include <optional>     // std::optional, std::make_optional
#include <cstdint>      // uint32_t etc
#include <string_view>  // std::string_view
#include <vector>

#if WIN32
    #define BREAK()             __debugbreak()
#else // we assume macos for now
    #define BREAK()             __builtin_trap()
#endif

#define cast                reinterpret_cast
#define check(expr, ...)    if (!bool(expr)) { printf("ASSERT - %s[%d]: ", __FILE__, __LINE__);    \
                                               printf(__VA_ARGS__); printf("\n"); BREAK(); }

auto debug_hex_dump(const void* in, size_t len) -> void;

template <typename T>
static constexpr auto kb(T v) -> T { return v * (T) 1024; }

template <typename T>
static constexpr auto mb(T v) -> T { return kb(v) * (T) 1024; }

template <typename T>
static constexpr auto align(T value, T alignment) -> T {
    return (value + alignment - 1) & ~(alignment - 1);
}

template <typename T>
static constexpr auto isBitSet(T value, unsigned int bit) -> bool {
    return (value & bit) != 0;
}

struct StringHash {
    constexpr StringHash() = default;
    constexpr StringHash(const std::string_view& view) : StringHash(view.data()) {}
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

    constexpr auto getStart() const { return begin; }
    constexpr auto   getEnd() const { return end; }

    template <typename RT>
    constexpr auto to() -> Range<RT> { return { (RT) begin, (RT) end }; }

    constexpr auto operator==(Range other) const -> bool { return begin == other.begin && end == other.end; }
    constexpr auto operator!=(Range other) const -> bool { return ! (*this == other); }

    static auto fromOffsetAndLength(T offset, T length) {
        return Range{ offset, offset + length };
    }

private:
    T begin, end;
};

template <typename T>
static auto rangeFromLength(T start, size_t length) {
    return Range<T> { start, (T) start + length };
}

template<typename T>
struct View {
    constexpr View()                    : View(nullptr, nullptr) {}
    constexpr View(T* _first, T* _last) : first(_first), last(_last) {}

    constexpr       auto   size() const { return static_cast<size_t>(last - first); }
    constexpr const auto  begin() const { return first; }
    constexpr const auto    end() const { return last; }
    constexpr const auto   data() const { return first; }
    constexpr const auto& front() const { return first[0]; }
    constexpr const auto&  back() const { return first[size()-1]; }
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

std::optional<std::vector<uint8_t>> file_load(const std::string_view& path);
bool file_save(const std::string_view& path, const void* data, int len);
