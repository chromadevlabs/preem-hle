
#include <string>
#include <string_view>
#include <vector>

#include "coredll_symbols.h"

using std::string_view;
using std::string;
using std::vector;
using std::pair;

struct Module {
    string name;
    vector<pair<string, void*>> symbols;
};

static vector<Module> modules;

void module_register_function(const string_view& module, const string_view& symbol, const void*) {

}

const void* module_symbol_lookup(const string_view& module, const string_view& symbol) {

}

const char* module_ordinal_lookup(const string_view& module, uint16_t ordinal) {
    if (module == "COREDLL.dll") {
        for (const auto& sym : coredll_symbols) {
            if (sym.ord == ordinal) {
                return sym.name;
            }
        }
    }

    return nullptr;
}