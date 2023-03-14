

#include <memory>

#include "utils.h"

using ptr          = std::unique_ptr<FILE, void(*)(FILE*)>;

static void closer(FILE* f) { if (f) fclose(f);  };

optional<vector<uint8_t>> file_load(const string_view& path) {
    if (auto file = ptr(fopen(path.data(), "rb"), closer)) {
        fseek(file.get(), 0, SEEK_END);
        if (auto size = ftell(file.get()); size > 0) {
            vector<uint8_t> data;

            data.resize(size);
            fseek(file.get(), 0, SEEK_SET);
            fread(data.data(), 1, size, file.get());

            return make_optional(data);
        }
    }

    return {};
}

bool file_save(const string_view& path, const vector<uint8_t>& data) {
    if (auto file = ptr(fopen(path.data(), "wb"), closer)) {
        fwrite(data.data(), 1, data.size(), file.get());
        return true;
    }

    return false;
}