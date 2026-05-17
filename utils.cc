

#include <memory>

#include "utils.h"

using ptr = std::unique_ptr<FILE, void(*)(FILE*)>;

static void closer(FILE* f) { if (f) fclose(f);  };

std::optional<std::vector<uint8_t>> file_load(const std::string_view& path) {
    if (auto file = ptr(fopen(path.data(), "rb"), closer)) {
        fseek(file.get(), 0, SEEK_END);
        if (auto size = ftell(file.get()); size > 0) {
            std::vector<uint8_t> data;

            data.resize(size);
            fseek(file.get(), 0, SEEK_SET);
            fread(data.data(), 1, size, file.get());

            return std::make_optional(data);
        }
    }

    return {};
}

bool file_save(const std::string_view& path, const void* data, int len) {
    if (auto file = ptr(fopen(path.data(), "wb"), closer)) {
        fwrite(data, 1, len, file.get());
        return true;
    }

    return false;
}

auto debug_hex_dump(const void* in, size_t len) -> void {
    constexpr auto byteWidth = 16;

    size_t offset = 0;
    const auto data = (const uint8_t*) in;

    while (offset < len) {
        const auto stride = std::min<size_t>(byteWidth, len - offset);

        printf("0x%04zX:\t", offset);

        for (size_t i = 0; i < byteWidth; i++) {
            if (i < stride)
                printf("%02X ", data[offset + i]);
            else
                printf("   ");
        }

        printf("\t");
        for (size_t i = 0; i < byteWidth; i++) {
            if (i < stride)
                printf("%c", (isprint(data[offset + i]) ? (char) data[offset + i] : '.'));
            else
                printf(".");
        }

        printf("\n");
        offset += stride;
    }
}
