

#include <memory>

#include "utils.h"

optional<vector<byte>> file_load(const string_view& path) {
    using ptr   = std::unique_ptr<FILE, void(*)(FILE*)>;
    auto closer = [](FILE* f){ if (f) fclose(f); };

    if (auto file = ptr(fopen(path.data(), "rb"), closer)) {
        fseek(file.get(), 0, SEEK_END);
        if (auto size = ftell(file.get()); size > 0) {
            std::vector<std::byte> data;

            data.resize(size);
            fseek(file.get(), 0, SEEK_SET);
            fread(data.data(), 1, size, file.get());

            return make_optional(data);
        }
    }

    return {};
}