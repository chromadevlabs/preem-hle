
#include "disassembler.h"
#include "process.h"
#include "utils.h"

#include <capstone/capstone.h>
#include <cstdio>
#include <cstring>
#include <vector>

static csh handle_arm = 0;
static csh handle_thumb = 0;

static void init_cs(csh& handle, cs_mode mode) {
    auto r = cs_open(CS_ARCH_ARM, mode, &handle);
    check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));

    r = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));

    r = cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);
    check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));
}

void disassembler_init() {
    init_cs(handle_arm,   CS_MODE_ARM);
    init_cs(handle_thumb, CS_MODE_THUMB);
}

void disassembler_shutdown() {
    if (handle_arm) {
        cs_close(&handle_arm);
        handle_arm = 0;
    }
    if (handle_thumb) {
        cs_close(&handle_thumb);
        handle_thumb = 0;
    }
}

static uint32_t reg_u32(unsigned reg) {
    switch (reg) {
        case ARM_REG_R0:  return process_reg_read_u32(Register::r0);
        case ARM_REG_R1:  return process_reg_read_u32(Register::r1);
        case ARM_REG_R2:  return process_reg_read_u32(Register::r2);
        case ARM_REG_R3:  return process_reg_read_u32(Register::r3);
        case ARM_REG_R4:  return process_reg_read_u32(Register::r4);
        case ARM_REG_R5:  return process_reg_read_u32(Register::r5);
        case ARM_REG_R6:  return process_reg_read_u32(Register::r6);
        case ARM_REG_R7:  return process_reg_read_u32(Register::r7);
        case ARM_REG_R8:  return process_reg_read_u32(Register::r8);
        case ARM_REG_R9:  return process_reg_read_u32(Register::r9);
        case ARM_REG_R10: return process_reg_read_u32(Register::r10);
        case ARM_REG_R11: return process_reg_read_u32(Register::r11);
        case ARM_REG_R12: return process_reg_read_u32(Register::r12);
        case ARM_REG_SP:  return process_reg_read_u32(Register::sp);
        case ARM_REG_LR:  return process_reg_read_u32(Register::lr);
        case ARM_REG_PC:  return process_reg_read_u32(Register::pc);
    }

    return 0;
}

static constexpr const char* reg_name(unsigned reg) {
    switch (reg) {
        case ARM_REG_R0:  return "r0";
        case ARM_REG_R1:  return "r1";
        case ARM_REG_R2:  return "r2";
        case ARM_REG_R3:  return "r3";
        case ARM_REG_R4:  return "r4";
        case ARM_REG_R5:  return "r5";
        case ARM_REG_R6:  return "r6";
        case ARM_REG_R7:  return "r7";
        case ARM_REG_R8:  return "r8";
        case ARM_REG_R9:  return "r9";
        case ARM_REG_R10: return "r10";
        case ARM_REG_R11: return "r11";
        case ARM_REG_R12: return "r12";
        case ARM_REG_SP:  return "sp";
        case ARM_REG_LR:  return "lr";
        case ARM_REG_PC:  return "pc";
    }

    return nullptr;
}

static int fmt_shift_str(char* buf, int sz, arm_shifter type, unsigned val) {
    switch (type) {
        case ARM_SFT_LSL: return snprintf(buf, sz, " << %u", val);
        case ARM_SFT_LSR: return snprintf(buf, sz, " >> %u", val);
        case ARM_SFT_ASR: return snprintf(buf, sz, " s>> %u", val);
        case ARM_SFT_ROR: return snprintf(buf, sz, " ror %u", val);
    }

    return 0;
}

static int fmt_reg_shifted(char* buf, int sz, const cs_arm_op& op) {
    int p = snprintf(buf, sz, "%s", reg_name(op.reg));

    if (op.shift.type != ARM_SFT_INVALID && op.shift.value)
        p += fmt_shift_str(buf + p, sz - p, op.shift.type, op.shift.value);

    return p;
}

static int fmt_mem_addr(char* buf, int sz, const cs_arm_op& op,
                        uint32_t pc_val) {
    if (op.mem.base == ARM_REG_PC)
        return snprintf(buf, sz, "0x%08X",
                        (uint32_t)((int32_t)pc_val + op.mem.disp));

    int pos = 0;
    if (op.mem.base != ARM_REG_INVALID)
        pos += snprintf(buf + pos, sz - pos, "%s", reg_name(op.mem.base));

    if (op.mem.index != ARM_REG_INVALID) {
        pos += snprintf(buf + pos, sz - pos, " + %s", reg_name(op.mem.index));
        if (op.shift.type != ARM_SFT_INVALID && op.shift.value)
            pos += fmt_shift_str(buf + pos, sz - pos, op.shift.type,
                                 op.shift.value);
    }

    if (op.mem.disp > 0)
        pos += snprintf(buf + pos, sz - pos, " + %d", op.mem.disp);
    else if (op.mem.disp < 0)
        pos += snprintf(buf + pos, sz - pos, " - %d", -op.mem.disp);

    return pos;
}

static std::string describe_insn(const cs_insn* insn, bool isThumb, uint32_t address) {
    static constexpr auto sz = 512;
    char buf[sz]{};
    int pos = 0;

    const auto& arm = insn->detail->arm;
    const int n = arm.op_count;
    const uint32_t pc_val = (address & ~3u) + (isThumb ? 4u : 8u);

#define line(fmt, ...) pos += snprintf(buf + pos, sz - pos, fmt, ##__VA_ARGS__)

    auto reg_op = [&](int i) {
        char tmp[48]{};
        fmt_reg_shifted(tmp, sizeof(tmp), arm.operands[i]);
        line("%s", tmp);
    };

    auto imm_op = [&](int i) {
        auto v = (uint32_t)arm.operands[i].imm;

        if (v > 9)
            line("0x%X", v);
        else
            line("%u", v);
    };

    auto any_op = [&](int i) {
        const auto& op = arm.operands[i];

        if (op.type == ARM_OP_REG)
            reg_op(i);
        else if (op.type == ARM_OP_IMM)
            imm_op(i);
    };

    auto mem_op = [&](int i, const char* type) {
        char addr[64]{};

        fmt_mem_addr(addr, sizeof(addr), arm.operands[i], pc_val);
        line("*(%s*)(%s)", type, addr);
    };

    if (arm.cc != ARMCC_AL && arm.cc != ARMCC_Invalid) {
        const char* cc = "?";

        switch (arm.cc) {
            case ARMCC_EQ:
                cc = "EQ";
                break;
            case ARMCC_NE:
                cc = "NE";
                break;
            case ARMCC_HS:
                cc = "HS";
                break;
            case ARMCC_LO:
                cc = "LO";
                break;
            case ARMCC_MI:
                cc = "MI";
                break;
            case ARMCC_PL:
                cc = "PL";
                break;
            case ARMCC_VS:
                cc = "VS";
                break;
            case ARMCC_VC:
                cc = "VC";
                break;
            case ARMCC_HI:
                cc = "HI";
                break;
            case ARMCC_LS:
                cc = "LS";
                break;
            case ARMCC_GE:
                cc = "GE";
                break;
            case ARMCC_LT:
                cc = "LT";
                break;
            case ARMCC_GT:
                cc = "GT";
                break;
            case ARMCC_LE:
                cc = "LE";
                break;
            default:
                break;
        }

        line("if(%s) ", cc);
    }

    switch (insn->id) {
    case ARM_INS_MOV:
    case ARM_INS_MOVW:
        if (n >= 2) {
            reg_op(0);
            line(" = ");
            any_op(1);
        }
        break;

    case ARM_INS_MVN:
        if (n >= 2) {
            reg_op(0);
            line(" = ~");
            any_op(1);
        }
        break;
    case ARM_INS_MOVT:
        if (n >= 2) {
            reg_op(0);
            line("[31:16] = ");
            any_op(1);
        }
        break;

    case ARM_INS_ADD:
    case ARM_INS_ADDW:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" + ");
            any_op(2);
        } else if (n == 2) {
            reg_op(0);
            line(" += ");
            any_op(1);
        }
        break;
    case ARM_INS_SUB:
    case ARM_INS_SUBW:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" - ");
            any_op(2);
        } else if (n == 2) {
            reg_op(0);
            line(" -= ");
            any_op(1);
        }
        break;
    case ARM_INS_RSB:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(2);
            line(" - ");
            any_op(1);
        }
        break;
    case ARM_INS_ADC:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" + ");
            any_op(2);
            line(" + C");
        }
        break;
    case ARM_INS_SBC:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" - ");
            any_op(2);
            line(" - !C");
        }
        break;
    case ARM_INS_MUL:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" * ");
            any_op(2);
        }
        break;
    case ARM_INS_MLA:
        if (n == 4) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" * ");
            any_op(2);
            line(" + ");
            any_op(3);
        }
        break;
    case ARM_INS_MLS:
        if (n == 4) {
            reg_op(0);
            line(" = ");
            any_op(3);
            line(" - ");
            any_op(1);
            line(" * ");
            any_op(2);
        }
        break;
    case ARM_INS_SDIV:
        if (n == 3) {
            reg_op(0);
            line(" = (s32)");
            any_op(1);
            line(" / (s32)");
            any_op(2);
        }
        break;
    case ARM_INS_UDIV:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" / ");
            any_op(2);
        }
        break;

    case ARM_INS_AND:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" & ");
            any_op(2);
        } else if (n == 2) {
            reg_op(0);
            line(" &= ");
            any_op(1);
        }
        break;
    case ARM_INS_ORR:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" | ");
            any_op(2);
        } else if (n == 2) {
            reg_op(0);
            line(" |= ");
            any_op(1);
        }
        break;
    case ARM_INS_EOR:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" ^ ");
            any_op(2);
        } else if (n == 2) {
            reg_op(0);
            line(" ^= ");
            any_op(1);
        }
        break;
    case ARM_INS_BIC:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" & ~");
            any_op(2);
        }
        break;
    case ARM_INS_ORN:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" | ~");
            any_op(2);
        }
        break;

    case ARM_INS_LSL:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" << ");
            any_op(2);
        }
        break;
    case ARM_INS_LSR:
        if (n == 3) {
            reg_op(0);
            line(" = ");
            any_op(1);
            line(" >> ");
            any_op(2);
        }
        break;
    case ARM_INS_ASR:
        if (n == 3) {
            reg_op(0);
            line(" = (s32)");
            any_op(1);
            line(" >> ");
            any_op(2);
        }
        break;
    case ARM_INS_ROR:
        if (n == 3) {
            reg_op(0);
            line(" = ror(");
            any_op(1);
            line(", ");
            any_op(2);
            line(")");
        }
        break;
    case ARM_INS_RRX:
        if (n == 2) {
            reg_op(0);
            line(" = rrx(");
            any_op(1);
            line(")");
        }
        break;

    case ARM_INS_CMP:
        if (n == 2) {
            line("flags(");
            any_op(0);
            line(" - ");
            any_op(1);
            line(")");
        }
        break;
    case ARM_INS_CMN:
        if (n == 2) {
            line("flags(");
            any_op(0);
            line(" + ");
            any_op(1);
            line(")");
        }
        break;
    case ARM_INS_TST:
        if (n == 2) {
            line("flags(");
            any_op(0);
            line(" & ");
            any_op(1);
            line(")");
        }
        break;
    case ARM_INS_TEQ:
        if (n == 2) {
            line("flags(");
            any_op(0);
            line(" ^ ");
            any_op(1);
            line(")");
        }
        break;

    case ARM_INS_LDR:
        if (n == 2) {
            reg_op(0);
            line(" = ");
            mem_op(1, "u32");
        }
        break;
    case ARM_INS_LDRB:
        if (n == 2) {
            reg_op(0);
            line(" = ");
            mem_op(1, "u8");
        }
        break;
    case ARM_INS_LDRH:
        if (n == 2) {
            reg_op(0);
            line(" = ");
            mem_op(1, "u16");
        }
        break;
    case ARM_INS_LDRSB:
        if (n == 2) {
            reg_op(0);
            line(" = ");
            mem_op(1, "s8");
        }
        break;
    case ARM_INS_LDRSH:
        if (n == 2) {
            reg_op(0);
            line(" = ");
            mem_op(1, "s16");
        }
        break;
    case ARM_INS_LDRD:
        if (n == 3) {
            reg_op(0);
            line(":");
            reg_op(1);
            line(" = ");
            mem_op(2, "u64");
        }
        break;

    case ARM_INS_STR:
        if (n == 2) {
            mem_op(1, "u32");
            line(" = ");
            reg_op(0);
        }
        break;
    case ARM_INS_STRB:
        if (n == 2) {
            mem_op(1, "u8");
            line(" = ");
            reg_op(0);
        }
        break;
    case ARM_INS_STRH:
        if (n == 2) {
            mem_op(1, "u16");
            line(" = ");
            reg_op(0);
        }
        break;
    case ARM_INS_STRD:
        if (n == 3) {
            mem_op(2, "u64");
            line(" = ");
            reg_op(0);
            line(":");
            reg_op(1);
        }
        break;

    case ARM_INS_B:
        if (n == 1) {
            if (arm.operands[0].type == ARM_OP_IMM)
                line("goto 0x%08X", (uint32_t)arm.operands[0].imm);
            else {
                line("goto ");
                reg_op(0);
            }
        }
        break;
    case ARM_INS_BL:
        if (n == 1 && arm.operands[0].type == ARM_OP_IMM)
            line("call 0x%08X", (uint32_t)arm.operands[0].imm);
        break;
    case ARM_INS_BX:
        if (n == 1) {
            if (arm.operands[0].reg == ARM_REG_LR)
                line("return");
            else {
                line("goto ");
                reg_op(0);
            }
        }
        break;
    case ARM_INS_BLX:
        if (n == 1) {
            line("call ");
            any_op(0);
        }
        break;
    case ARM_INS_CBZ:
        if (n == 2) {
            line("if(!");
            reg_op(0);
            line(") goto 0x%08X", (uint32_t)arm.operands[1].imm);
        }
        break;
    case ARM_INS_CBNZ:
        if (n == 2) {
            line("if(");
            reg_op(0);
            line(") goto 0x%08X", (uint32_t)arm.operands[1].imm);
        }
        break;

    case ARM_INS_PUSH:
        line("push {");
        for (int i = 0; i < n; i++) {
            if (i)
                line(", ");
            reg_op(i);
        }
        line("}");
        break;
    case ARM_INS_POP:
        line("pop {");
        for (int i = 0; i < n; i++) {
            if (i)
                line(", ");
            reg_op(i);
        }
        line("}");
        break;

    case ARM_INS_LDM:
    case ARM_INS_LDMDA:
    case ARM_INS_LDMDB:
    case ARM_INS_LDMIB:
        if (n >= 2) {
            reg_op(0);
            line(" -> {");
            for (int i = 1; i < n; i++) {
                if (i > 1)
                    line(", ");
                reg_op(i);
            }
            line("}");
        }
        break;
    case ARM_INS_STM:
    case ARM_INS_STMDA:
    case ARM_INS_STMDB:
    case ARM_INS_STMIB:
        if (n >= 2) {
            reg_op(0);
            line(" <- {");
            for (int i = 1; i < n; i++) {
                if (i > 1)
                    line(", ");
                reg_op(i);
            }
            line("}");
        }
        break;

    case ARM_INS_UXTB:
        if (n >= 2) {
            reg_op(0);
            line(" = (u8)");
            any_op(1);
        }
        break;
    case ARM_INS_UXTH:
        if (n >= 2) {
            reg_op(0);
            line(" = (u16)");
            any_op(1);
        }
        break;
    case ARM_INS_SXTB:
        if (n >= 2) {
            reg_op(0);
            line(" = (s8)");
            any_op(1);
        }
        break;
    case ARM_INS_SXTH:
        if (n >= 2) {
            reg_op(0);
            line(" = (s16)");
            any_op(1);
        }
        break;

    case ARM_INS_CLZ:
        if (n == 2) {
            reg_op(0);
            line(" = clz(");
            any_op(1);
            line(")");
        }
        break;
    case ARM_INS_RBIT:
        if (n == 2) {
            reg_op(0);
            line(" = rbit(");
            any_op(1);
            line(")");
        }
        break;
    case ARM_INS_REV:
        if (n == 2) {
            reg_op(0);
            line(" = bswap(");
            any_op(1);
            line(")");
        }
        break;
    case ARM_INS_UBFX:
        if (n == 4) {
            uint32_t width = (uint32_t)arm.operands[3].imm;
            reg_op(0);
            line(" = (");
            any_op(1);
            line(" >> ");
            imm_op(2);
            line(") & 0x%X", (1u << width) - 1);
        }
        break;
    case ARM_INS_SBFX:
        if (n == 4) {
            reg_op(0);
            line(" = sign_ext(");
            any_op(1);
            line(" >> ");
            imm_op(2);
            line(", ");
            imm_op(3);
            line(")");
        }
        break;
    case ARM_INS_BFI:
        if (n == 4) {
            reg_op(0);
            line("[");
            imm_op(2);
            line(",+");
            imm_op(3);
            line("] = ");
            any_op(1);
        }
        break;
    case ARM_INS_BFC:
        if (n == 3) {
            reg_op(0);
            line("[");
            imm_op(1);
            line(",+");
            imm_op(2);
            line("] = 0");
        }
        break;

    default:
        break;
    }

    // Flag update suffix (S), except for compare/test where it is always
    // implicit.
    if (arm.update_flags && pos > 0) {
        switch (insn->id) {
        case ARM_INS_CMP:
        case ARM_INS_CMN:
        case ARM_INS_TST:
        case ARM_INS_TEQ:
            break;
        default:
            line("  [S]");
        }
    }

#undef line

    return buf;
}

void disassembler_oneshot(const uint8_t* code, uint32_t size, uint32_t address) {
    const bool isThumb = (process_reg_read_u32(Register::cpsr) >> 5) & 1;
    auto handle = isThumb ? handle_thumb
                          : handle_arm;

    cs_insn* insn = nullptr;
    char buf[512]{};
    int pos = 0;

#define line(fmt, ...) \
    pos += snprintf(buf + pos, sizeof (buf) - pos, fmt, ##__VA_ARGS__)

    line("Thread %d - 0x%08X: ", process_get_current_thread()->id, address);

    if (const auto n = cs_disasm(handle, code, size, address, 1, &insn)) {
        char instr[256]{};
        snprintf(instr, sizeof (instr),
                 " %-6s %s",
                 insn->mnemonic,
                 insn->op_str);

        const auto states = [insn] {
            std::string string;

            const auto& arm = insn->detail->arm;
            std::vector<int> visitedRegisters;

            for (int i = 0; i < arm.op_count; i++) {
                auto reg = arm.operands[i].reg;

                const auto name = reg_name(reg);
                const auto visited = std::find(visitedRegisters.begin(),
                                               visitedRegisters.end(),
                                               reg) != visitedRegisters.end();

                if (name && ! visited) {
                    char buf[100]{};
                    snprintf(buf, sizeof (buf),
                             "%s = 0x%X, ",
                             name,
                             reg_u32(reg));

                    string += buf;
                    visitedRegisters.push_back(reg);
                }
            }

            return string;
        }();

        const auto desc = describe_insn(insn, isThumb, address);
        line("%-30s %-25s    %s", instr, desc.c_str(), states.c_str());

        cs_free(insn, n);
    }

#undef line

    printf("%s\n", buf);
}
