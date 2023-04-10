
#include "disassembler.h"
#include "utils.h"

#include <capstone/capstone.h>

static csh cs = 0;

void disassembler_init() {
    auto r = cs_open(cs_arch::CS_ARCH_ARM, cs_mode::CS_MODE_ARM, &cs);
    check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));

    // Required???
    r = cs_option(cs, cs_opt_type::CS_OPT_DETAIL, CS_OPT_ON);
    check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));
    r = cs_option(cs, cs_opt_type::CS_OPT_SKIPDATA, CS_OPT_OFF);
    check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));
}

void disassembler_shutdown() {
    if (cs)
        cs_close(&cs);
}

void disassembler_oneshot(const Process* p, const uint8_t* code, uint32_t size, uint32_t address) {
    cs_insn* insn = nullptr;
    int printOffset = 0;

    printOffset += print("0x%08X: %02X%02X%02X%02X", address, code[0], code[1], code[2], code[3]);

    if (const auto n = cs_disasm(cs, code, size, address, 1, &insn)) {
        printOffset += print("    %-5s %s", insn[0].mnemonic, insn[0].op_str);

        if (const auto d = insn[0].detail) {
            printOffset += print("; ");

            // I can't for the life of me remember how to make printf align to the right.. so :shrug:
            while (printOffset < 55)
                printOffset += print(" ");

            for (auto op : make_view(d->arm.operands, d->arm.operands + d->arm.op_count)) {
                if (op.type == ARM_OP_REG) {
                    switch (op.reg) {
                    case ARM_REG_R0:  print("r0[0x%08X] ", process_reg_read(p, Register::r0)); break;
                    case ARM_REG_R1:  print("r1[0x%08X] ", process_reg_read(p, Register::r1)); break;
                    case ARM_REG_R2:  print("r2[0x%08X] ", process_reg_read(p, Register::r2)); break;
                    case ARM_REG_R3:  print("r3[0x%08X] ", process_reg_read(p, Register::r3)); break;
                    case ARM_REG_R4:  print("r4[0x%08X] ", process_reg_read(p, Register::r4)); break;
                    case ARM_REG_R5:  print("r5[0x%08X] ", process_reg_read(p, Register::r5)); break;
                    case ARM_REG_R6:  print("r6[0x%08X] ", process_reg_read(p, Register::r6)); break;
                    case ARM_REG_R7:  print("r7[0x%08X] ", process_reg_read(p, Register::r7)); break;
                    case ARM_REG_R8:  print("r8[0x%08X] ", process_reg_read(p, Register::r8)); break;
                    case ARM_REG_R9:  print("r9[0x%08X] ", process_reg_read(p, Register::r9)); break;
                    case ARM_REG_R10: print("r10[0x%08X] ", process_reg_read(p, Register::r10)); break;
                    case ARM_REG_R11: print("r11[0x%08X] ", process_reg_read(p, Register::r11)); break;
                    case ARM_REG_SP:  print("sp[0x%08X] ", process_reg_read(p, Register::sp)); break;
                    case ARM_REG_LR:  print("lr[0x%08X] ", process_reg_read(p, Register::lr)); break;
                    case ARM_REG_PC:  print("pc[0x%08X] ", process_reg_read(p, Register::pc)); break;
                    case ARM_REG_IP:  print("ip[0x%08X] ", process_reg_read(p, Register::ip)); break;
                    }
                }
            }
        }

        cs_free(insn, n);
        print("\n");
    }
}