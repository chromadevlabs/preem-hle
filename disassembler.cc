
#include "disassembler.h"
#include "utils.h"

#include <capstone/capstone.h>

static csh          cs = 0;

void disassembler_init() {
    auto r = cs_open(cs_arch::CS_ARCH_ARM, cs_mode::CS_MODE_ARM, &cs);
    check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));

    r = cs_option(cs, cs_opt_type::CS_OPT_DETAIL, CS_OPT_ON);
    check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));
    r = cs_option(cs, cs_opt_type::CS_OPT_SKIPDATA, CS_OPT_OFF);
    check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));
}

void disassembler_shutdown() {
    cs_close(&cs);
}

void disassembler_oneshot(const Process* p, const uint8_t* code, size_t size, uint32_t address) {
    cs_insn* insn = nullptr;

    print("0x%08X: %02X%02X%02X%02X", address, code[0], code[1], code[2], code[3]);

    if (const auto n = cs_disasm(cs, code, size, address, 1, &insn)) {
        print("\t%-5s %s", insn[0].mnemonic, insn[0].op_str);

        if (const auto d = insn[0].detail) {
            print("; ");

            for (auto op : make_view(d->arm.operands, d->arm.operands + d->arm.op_count)) {
                if (op.type == ARM_OP_REG) {
                    const auto regIndex = op.reg - ARM_REG_R0;

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
                    case ARM_REG_R9: print("r%d[0x%08X] ", regIndex, process_register_read(p, (RegisterIndex)regIndex)); break;
                    case ARM_REG_SP: print("sp[0x%08X] ", process_register_read(p, RegisterIndex::Reg_sp)); break;
                    case ARM_REG_LR: print("lr[0x%08X] ", process_register_read(p, RegisterIndex::Reg_lr)); break;
                    case ARM_REG_PC: print("pc[0x%08X] ", process_register_read(p, RegisterIndex::Reg_pc)); break;
                    case ARM_REG_IP: print("ip[0x%08X] ", process_register_read(p, RegisterIndex::Reg_ip)); break;
                    }
                }
            }
        }

        cs_free(insn, n);
        print("\n");
    }
}