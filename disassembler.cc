
#include "disassembler.h"
#include "utils.h"

#include <capstone/capstone.h>
#include <string>

static csh cs = 0;

namespace disassembler {
    void init() {
        auto r = cs_open(cs_arch::CS_ARCH_ARM, cs_mode::CS_MODE_ARM, &cs);
        check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));

        r = cs_option(cs, cs_opt_type::CS_OPT_DETAIL, CS_OPT_ON);
        check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));
        r = cs_option(cs, cs_opt_type::CS_OPT_SKIPDATA, CS_OPT_OFF);
        check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));
    }

    void shutdown() {
        cs_close(&cs);
    }

    void oneshit(const uint8_t* code, size_t size, uint32_t address) {
        cs_insn* insn = nullptr;
        std::string string;

        string_writer_append(sw, "0x%08X: %02X%02X%02X%02X", address, code[0], code[1], code[2], code[3]);

        if (const auto n = cs_disasm(cs, code, size, address, 1, &insn)) {
            string_writer_append(sw, "\t%-5s %s", insn[0].mnemonic, insn[0].op_str);

            if (const auto d = insn[0].detail) {
                const Interop inter{uc};

                // I cannot make printf do this, I know its possible but I just cannot.
                const auto padding = 50;
                while(sw.position < padding)
                    sw.buf[sw.position++] = ' ';

                string_writer_append(sw, "; ");

                for (auto op : make_view(d->arm.operands, d->arm.operands + d->arm.op_count)) {
                    if (op.type == ARM_OP_REG) {
                        switch (op.reg) {
                            case ARM_REG_R0:
                            case ARM_REG_R1:
                            case ARM_REG_R2:
                            case ARM_REG_R3:
                            case ARM_REG_R4:
                            case ARM_REG_R5:
                            case ARM_REG_R6:
                            case ARM_REG_R7:
                            case ARM_REG_R8:
                            case ARM_REG_R9: string_writer_append(sw, "r%d[0x%08X] ", op.reg - ARM_REG_R0, inter.read(op.reg - ARM_REG_R0)); break;
                            case ARM_REG_SP: string_writer_append(sw, "sp[0x%08X] ", inter.readSP()); break;
                            case ARM_REG_LR: string_writer_append(sw, "lr[0x%08X] ", inter.readLR()); break;
                            case ARM_REG_PC: string_writer_append(sw, "pc[0x%08X] ", inter.readPC()); break;
                            case ARM_REG_IP: string_writer_append(sw, "ip[0x%08X] ", inter.readIP()); break;
                        }
                    }
                }
            }

            cs_free(insn, n);
            printf("%s\n", sw.buf);
        }
    }
}