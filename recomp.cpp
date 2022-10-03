#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <string_view>

#include <capstone.h>

#include "rabbitizer.h"

#include "elf.h"

#if defined(_WIN32) && !defined(__CYGWIN__)
#include <windows.h>
#endif /* _WIN32 && !__CYGWIN__ */

#define INSPECT_FUNCTION_POINTERS \
    0 // set this to 1 when testing a new program, to verify that no false function pointers are found

#ifndef TRACE
#define TRACE 0
#endif

#define LABELS_64_BIT 1

#define u32be(x) (uint32_t)(((x & 0xff) << 24) + ((x & 0xff00) << 8) + ((x & 0xff0000) >> 8) + ((uint32_t)(x) >> 24))
#define u16be(x) (uint16_t)(((x & 0xff) << 8) + ((x & 0xff00) >> 8))
#define read_u32_be(buf) (uint32_t)(((buf)[0] << 24) + ((buf)[1] << 16) + ((buf)[2] << 8) + ((buf)[3]))

using namespace std;

struct Edge {
    uint32_t i;
    uint8_t function_entry : 1;
    uint8_t function_exit : 1;
    uint8_t extern_function : 1;
    uint8_t function_pointer : 1;
};

struct Insn {
    uint32_t id;
    uint8_t op_count;
    string mnemonic;
    string op_str;
    cs_mips_op operands[8];

    uint8_t is_jump : 1;
    uint8_t is_global_got_memop : 1;
    uint8_t no_following_successor : 1;
    int linked_insn;
    union {
        uint32_t linked_value;
        float linked_float;
    };
    uint32_t jtbl_addr;
    uint32_t num_cases;
    mips_reg index_reg;
    vector<Edge> successors;
    vector<Edge> predecessors;
    uint64_t b_liveout;
    uint64_t b_livein;
    uint64_t f_livein;
    uint64_t f_liveout;
};

struct RInsn {
    // base instruction
    RabbitizerInstruction instruction;
    RabbitizerInstrDescriptor descriptor;

    //
    bool is_global_got_memop;
    bool no_following_successor;

    // patching instructions
    bool patched;
    // lui pairs
    uint32_t patched_addr;
    int linked_insn;
    union {
        uint32_t linked_value;
        float linked_float;
    };
    // jumptable instructions
    uint32_t jtbl_addr;
    uint32_t num_cases;
    RabbitizerRegister_GprO32 index_reg;

    // graph
    vector<Edge> successors;
    vector<Edge> predecessors;
    uint64_t b_liveout;
    uint64_t b_livein;
    uint64_t f_livein;
    uint64_t f_liveout;
};

struct Function {
    vector<uint32_t> returns; // points to delay slots
    uint32_t end_addr;        // address after end
    uint32_t nargs;
    uint32_t nret;
    bool v0_in;
    bool referenced_by_function_pointer;
};

static bool conservative;

static csh handle;

static const uint8_t* text_section;
static uint32_t text_section_len;
static uint32_t text_vaddr;

static const uint8_t* rodata_section;
static uint32_t rodata_section_len;
static uint32_t rodata_vaddr;

static const uint8_t* data_section;
static uint32_t data_section_len;
static uint32_t data_vaddr;

static uint32_t bss_section_len;
static uint32_t bss_vaddr;

static vector<RInsn> rinsns;
static vector<Insn> insns;
static set<uint32_t> label_addresses;
static vector<uint32_t> got_globals;
static vector<uint32_t> got_locals;
static uint32_t gp_value;
static uint32_t gp_value_adj;

static map<uint32_t, string> symbol_names;

static vector<pair<uint32_t, uint32_t>> data_function_pointers;
static set<uint32_t> li_function_pointers;
static map<uint32_t, Function> functions;
static uint32_t main_addr;
static uint32_t mcount_addr;
static uint32_t procedure_table_start;
static uint32_t procedure_table_len;

#define FLAG_NO_MEM 1
#define FLAG_VARARG 2

/**
 * Struct containing information on external functions that are called using the wrappers in `libc_impl.c`.
 *
 * name:    function name
 * params:  first char is return type, subsequent chars are argument types. Key to chars used:
 *          - 'v' void
 *          - 'i' signed int (int32_t)
 *          - 'u' unsigned int (uint32_t)
 *          - 'p' pointer (uintptr_t)
 *          - 'f' float
 *          - 'd' double
 *          - 'l' signed long long (int64_t)
 *          - 'j' unsigned long long (uint64_t)
 *          - 't' trampoline
 *
 * flags:   use defines above
 */
static const struct ExternFunction {
    const char* name;
    const char* params;
    int flags;
} extern_functions[] = {
    { "exit", "vi", 0 }, // override exit from application
    { "abort", "v", 0 },
    { "sbrk", "pi", 0 },
    { "malloc", "pu", 0 },
    { "calloc", "puu", 0 },
    { "realloc", "ppu", 0 },
    { "free", "vp", 0 },
    { "fscanf", "ipp", FLAG_VARARG },
    { "printf", "ip", FLAG_VARARG },
    { "sprintf", "ipp", FLAG_VARARG },
    { "fprintf", "ipp", FLAG_VARARG },
    { "_doprnt", "ippp", 0 },
    { "strlen", "up", 0 },
    { "open", "ipii", 0 },
    { "creat", "ipi", 0 },
    { "access", "ipi", 0 },
    { "rename", "ipp", 0 },
    { "utime", "ipp", 0 },
    { "flock", "iii", 0 },
    { "chmod", "ipu", 0 },
    { "umask", "ii", FLAG_NO_MEM },
    { "ecvt", "pdipp", 0 },
    { "fcvt", "pdipp", 0 },
    { "sqrt", "dd", FLAG_NO_MEM },
    { "sqrtf", "ff", FLAG_NO_MEM },
    { "atoi", "ip", 0 },
    { "atol", "ip", 0 },
    { "atof", "dp", 0 },
    { "strtol", "ippi", 0 },
    { "strtoul", "uppi", 0 },
    { "strtoll", "lppi", 0 },
    { "strtoull", "jppi", 0 },
    { "strtod", "dpp", 0 },
    { "strchr", "ppi", 0 },
    { "strrchr", "ppi", 0 },
    { "strcspn", "upp", 0 },
    { "strpbrk", "ppp", 0 },
    { "fstat", "iip", 0 },
    { "stat", "ipp", 0 },
    { "ftruncate", "iii", 0 },
    { "bcopy", "vppu", 0 },
    { "memcpy", "pppu", 0 },
    { "memccpy", "pppiu", 0 },
    { "read", "iipu", 0 },
    { "write", "iipu", 0 },
    { "fopen", "ppp", 0 },
    { "freopen", "pppp", 0 },
    { "fclose", "ip", 0 },
    { "ftell", "ip", 0 },
    { "rewind", "vp", 0 },
    { "fseek", "ipii", 0 },
    { "lseek", "iiii", 0 },
    { "fflush", "ip", 0 },
    { "dup", "ii", 0 },
    { "dup2", "iii", 0 },
    { "pipe", "ip", 0 },
    { "perror", "vp", 0 },
    { "fdopen", "iip", 0 },
    { "memset", "ppiu", 0 },
    { "bcmp", "ippu", 0 },
    { "memcmp", "ippu", 0 },
    { "getpid", "i", FLAG_NO_MEM },
    { "getpgrp", "i", 0 },
    { "remove", "ip", 0 },
    { "unlink", "ip", 0 },
    { "close", "ii", 0 },
    { "strcmp", "ipp", 0 },
    { "strncmp", "ippu", 0 },
    { "strcpy", "ppp", 0 },
    { "strncpy", "pppu", 0 },
    { "strcat", "ppp", 0 },
    { "strncat", "pppu", 0 },
    { "strtok", "ppp", 0 },
    { "strstr", "ppp", 0 },
    { "strdup", "pp", 0 },
    { "toupper", "ii", FLAG_NO_MEM },
    { "tolower", "ii", FLAG_NO_MEM },
    { "gethostname", "ipu", 0 },
    { "isatty", "ii", 0 },
    { "strftime", "upupp", 0 },
    { "times", "ip", 0 },
    { "clock", "i", FLAG_NO_MEM },
    { "ctime", "pp", 0 },
    { "localtime", "pp", 0 },
    { "setvbuf", "ippiu", 0 },
    { "__semgetc", "ip", 0 },
    { "__semputc", "iip", 0 },
    { "fgetc", "ip", 0 },
    { "fgets", "ipip", 0 },
    { "__filbuf", "ip", 0 },
    { "__flsbuf", "iip", 0 },
    { "ungetc", "iip", 0 },
    { "gets", "pp", 0 },
    { "fread", "upuup", 0 },
    { "fwrite", "upuup", 0 },
    { "fputs", "ipp", 0 },
    { "puts", "ip", 0 },
    { "getcwd", "ppu", 0 },
    { "time", "ip", 0 },
    { "bzero", "vpu", 0 },
    { "fp_class_d", "id", FLAG_NO_MEM },
    { "ldexp", "ddi", FLAG_NO_MEM },
    { "__ll_mul", "lll", FLAG_NO_MEM },
    { "__ll_div", "lll", FLAG_NO_MEM },
    { "__ll_rem", "ljl", FLAG_NO_MEM },
    { "__ll_lshift", "llj", FLAG_NO_MEM },
    { "__ll_rshift", "llj", FLAG_NO_MEM },
    { "__ull_div", "jjj", FLAG_NO_MEM },
    { "__ull_rem", "jjj", FLAG_NO_MEM },
    { "__ull_rshift", "jjj", FLAG_NO_MEM },
    { "__d_to_ull", "jd", FLAG_NO_MEM },
    { "__d_to_ll", "ld", FLAG_NO_MEM },
    { "__f_to_ull", "jf", FLAG_NO_MEM },
    { "__f_to_ll", "lf", FLAG_NO_MEM },
    { "__ull_to_f", "fj", FLAG_NO_MEM },
    { "__ll_to_f", "fl", FLAG_NO_MEM },
    { "__ull_to_d", "dj", FLAG_NO_MEM },
    { "__ll_to_d", "dl", FLAG_NO_MEM },
    { "_exit", "vi", 0 },
    { "_cleanup", "v", 0 },
    { "_rld_new_interface", "pu", FLAG_VARARG },
    { "_exithandle", "v", 0 },
    { "_prctl", "ii", FLAG_VARARG },
    { "_atod", "dpii", 0 },
    { "pathconf", "ipi", 0 },
    { "getenv", "pp", 0 },
    { "gettxt", "ppp", 0 },
    { "setlocale", "pip", 0 },
    { "mmap", "ppuiiii", 0 },
    { "munmap", "ipu", 0 },
    { "mprotect", "ipui", 0 },
    { "sysconf", "ii", 0 },
    { "getpagesize", "i", 0 },
    { "strerror", "pi", 0 },
    { "ioctl", "iiu", FLAG_VARARG },
    { "fcntl", "iii", FLAG_VARARG },
    { "signal", "pit", 0 },
    { "sigset", "pit", 0 },
    { "get_fpc_csr", "i", 0 },
    { "set_fpc_csr", "ii", 0 },
    { "setjmp", "ip", 0 },
    { "longjmp", "vpi", 0 },
    { "tempnam", "ppp", 0 },
    { "tmpnam", "pp", 0 },
    { "mktemp", "pp", 0 },
    { "mkstemp", "ip", 0 },
    { "tmpfile", "p", 0 },
    { "wait", "ip", 0 },
    { "kill", "iii", 0 },
    { "execlp", "ip", FLAG_VARARG },
    { "execv", "ipp", 0 },
    { "execvp", "ipp", 0 },
    { "fork", "i", 0 },
    { "system", "ip", 0 },
    { "tsearch", "pppp", 0 },
    { "tfind", "pppp", 0 },
    { "qsort", "vpuut", 0 },
    { "regcmp", "pp", FLAG_VARARG },
    { "regex", "ppp", FLAG_VARARG },
    { "__assert", "vppi", 0 },
};

static void disassemble(void) {
    csh handle;
    cs_insn* disasm;
    size_t disasm_size = 0;

    assert(cs_open(CS_ARCH_MIPS, (cs_mode)(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN), &handle) == CS_ERR_OK);

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    insns.reserve(1 + text_section_len / sizeof(uint32_t)); // +1 for dummy instruction

    while (disasm_size * sizeof(uint32_t) < text_section_len) {
        size_t disasm_len = disasm_size * sizeof(uint32_t);
        size_t remaining = text_section_len - disasm_len;
        size_t current_len = std::min<size_t>(remaining, 1024);
        size_t cur_disasm_size =
            cs_disasm(handle, &text_section[disasm_len], current_len, text_vaddr + disasm_len, 0, &disasm);

        disasm_size += cur_disasm_size;
        for (size_t i = 0; i < cur_disasm_size; i++) {
            insns.push_back(Insn());

            Insn& insn = insns.back();

            insn.id = disasm[i].id;
            insn.mnemonic = disasm[i].mnemonic;
            insn.op_str = disasm[i].op_str;

            if (disasm[i].detail != nullptr && disasm[i].detail->mips.op_count > 0) {
                insn.op_count = disasm[i].detail->mips.op_count;
                memcpy(insn.operands, disasm[i].detail->mips.operands, sizeof(insn.operands));
            }

            insn.is_jump = cs_insn_group(handle, &disasm[i], MIPS_GRP_JUMP) || insn.id == MIPS_INS_JAL ||
                           insn.id == MIPS_INS_BAL || insn.id == MIPS_INS_JALR;
            insn.linked_insn = -1;
        }

        cs_free(disasm, cur_disasm_size);
    }

    cs_close(&handle);

    {
        // Add dummy instruction to avoid out of bounds
        insns.push_back(Insn());

        Insn& insn = insns.back();

        insn.id = MIPS_INS_NOP;
        insn.mnemonic = "nop";
        insn.no_following_successor = true;
    }
}

static void r_disassemble(void) {
    size_t i;
    for (i = 0; i < text_section_len; i += 4) {
        rinsns.push_back(RInsn());
        RInsn& insn = rinsns.back();
        RabbitizerInstruction instruction = insn.instruction;
        uint32_t word = read_u32_be(&text_section[i]);

        RabbitizerInstruction_init(&instruction, word, text_vaddr + i);
        RabbitizerInstruction_processUniqueId(&instruction);

        insn.linked_insn = -1;
    }
    {
        // Add dummy NOP instruction to avoid out of bounds
        rinsns.push_back(RInsn());
        RInsn& insn = rinsns.back();
        RabbitizerInstruction instruction = insn.instruction;

        RabbitizerInstruction_init(&instruction, 0x00000000, text_vaddr + i);
        RabbitizerInstruction_processUniqueId(&instruction);

        insn.no_following_successor = true;
    }
}

static void add_function(uint32_t addr) {
    if (addr >= text_vaddr && addr < text_vaddr + text_section_len) {
        functions[addr];
    }
}

static map<uint32_t, Function>::iterator find_function(uint32_t addr) {
    if (functions.size() == 0) {
        return functions.end();
    }

    auto it = functions.upper_bound(addr);

    if (it == functions.begin()) {
        return functions.end();
    }

    --it;
    return it;
}

// try to find a matching LUI for a given register
static void r_link_with_lui(int offset, RabbitizerRegister_GprO32 reg, int mem_imm) {
#define MAX_LOOKBACK 128
    // don't attempt to compute addresses for zero offset
    // end search after some sane max number of instructions
    int end_search = std::max(0, offset - MAX_LOOKBACK);

    for (int search = offset - 1; search >= end_search; search--) {

        switch (rinsns[search].instruction.uniqueId) {
            case RABBITIZER_INSTR_ID_cpu_lui:
                if (reg == RAB_INSTR_GET_rt(&rinsns[search].instruction)) {
                    goto end;
                }
                continue;

            case RABBITIZER_INSTR_ID_cpu_lw:
            case RABBITIZER_INSTR_ID_cpu_ld:
            case RABBITIZER_INSTR_ID_cpu_addiu:
            // case RABBITIZER_INSTR_ID_cpu_addu: // used in jump tables for offset
            case RABBITIZER_INSTR_ID_cpu_add:
            case RABBITIZER_INSTR_ID_cpu_sub:
            case RABBITIZER_INSTR_ID_cpu_subu:
                if (reg == RAB_INSTR_GET_rt(&rinsns[search].instruction)) {

                    if ((rinsns[search].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_lw) &&
                        RAB_INSTR_GET_rs(&rinsns[search].instruction) == RABBITIZER_REG_GPR_O32_gp) {
                        int mem_imm0 = (int)RAB_INSTR_GET_immediate(&rinsns[search].instruction);
                        uint32_t got_entry = (mem_imm0 + gp_value_adj) / sizeof(uint32_t);

                        if (got_entry < got_locals.size()) {
                            // used for static functions
                            char buf[32];
                            uint32_t addr = got_locals[got_entry] + mem_imm;
                            rinsns[search].linked_insn = offset;
                            rinsns[search].linked_value = addr;
                            rinsns[offset].linked_insn = search;
                            rinsns[offset].linked_value = addr;

                            // vaddr_references[addr].insert(text_vaddr + offset * 4);

                            // Patch instruction to contain full address
                            rinsns[search].patched = true;
                            rinsns[search].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_ori;
                            rinsns[search].instruction.descriptor =
                                &RabbitizerInstrDescriptor_Descriptors[rinsns[search].instruction.uniqueId];
                            rinsns[search].patched_addr = addr;
                            // TODO: handle printing separately for patched instructions

                            // Patch instruction to have offset 0
                            switch (rinsns[offset].instruction.uniqueId) {
                                case RABBITIZER_INSTR_ID_cpu_addiu:
                                    rinsns[offset].patched = true;
                                    rinsns[offset].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_move;
                                    rinsns[offset].instruction.descriptor =
                                        &RabbitizerInstrDescriptor_Descriptors[rinsns[search].instruction.uniqueId];

                                    if (addr >= text_vaddr && addr < text_vaddr + text_section_len) {
                                        add_function(addr);
                                    }
                                    goto end;

                                case RABBITIZER_INSTR_ID_cpu_lb:
                                case RABBITIZER_INSTR_ID_cpu_lbu:
                                case RABBITIZER_INSTR_ID_cpu_sb:
                                case RABBITIZER_INSTR_ID_cpu_lh:
                                case RABBITIZER_INSTR_ID_cpu_lhu:
                                case RABBITIZER_INSTR_ID_cpu_sh:
                                case RABBITIZER_INSTR_ID_cpu_lw:
                                case RABBITIZER_INSTR_ID_cpu_sw:
                                case RABBITIZER_INSTR_ID_cpu_ldc1:
                                case RABBITIZER_INSTR_ID_cpu_lwc1:
                                case RABBITIZER_INSTR_ID_cpu_swc1:
                                    rinsns[offset].patched = true;
                                    rinsns[offset].patched_addr = 0;
                                    goto end;

                                default:
                                    assert(0 && "Unsupported instruction type");
                            }
                        }
                        goto end;
                    } else {
                        // ignore: reg is pointer, offset is probably struct data member
                        goto end;
                    }
                }
                continue;

            case RABBITIZER_INSTR_ID_cpu_jr:
                if ((RAB_INSTR_GET_rd(&rinsns[search].instruction) == RABBITIZER_REG_GPR_O32_ra) &&
                    (offset - search >= 2)) {
                    // stop looking when previous `jr ra` is hit,
                    // but ignore if `offset` is branch delay slot for this `jr ra`
                    goto end;
                }
                continue;

            default:
                continue;
        }
    }
end:;
}

// try to find a matching LUI for a given register
static void link_with_lui(int offset, uint32_t reg, int mem_imm) {
#define MAX_LOOKBACK 128
    // don't attempt to compute addresses for zero offset
    // end search after some sane max number of instructions
    int end_search = std::max(0, offset - MAX_LOOKBACK);

    for (int search = offset - 1; search >= end_search; search--) {
        // use an `if` instead of `case` block to allow breaking out of the `for` loop
        // should be a switch with returns

        if (insns[search].id == MIPS_INS_LUI) {
            uint32_t rd = insns[search].operands[0].reg;

            if (reg == rd) {
                break;
            }
        } else if (insns[search].id == MIPS_INS_LW || insns[search].id == MIPS_INS_LD ||
                   insns[search].id == MIPS_INS_ADDIU ||
                   // insns[search].id == MIPS_INS_ADDU || // used in jump tables for offset
                   insns[search].id == MIPS_INS_ADD || insns[search].id == MIPS_INS_SUB ||
                   insns[search].id == MIPS_INS_SUBU) {
            uint32_t rd = insns[search].operands[0].reg;

            if (reg == rd) {
                if (insns[search].id == MIPS_INS_LW && insns[search].operands[1].mem.base == MIPS_REG_GP) {
                    int mem_imm0 = (int)insns[search].operands[1].mem.disp;
                    uint32_t got_entry = (mem_imm0 + gp_value_adj) / sizeof(uint32_t);
                    if (got_entry < got_locals.size()) {
                        // used for static functions
                        char buf[32];
                        uint32_t addr = got_locals[got_entry] + mem_imm;
                        insns[search].linked_insn = offset;
                        insns[search].linked_value = addr;
                        insns[offset].linked_insn = search;
                        insns[offset].linked_value = addr;

                        // vaddr_references[addr].insert(text_vaddr + offset * 4);

                        insns[search].id = MIPS_INS_LI;
                        insns[search].mnemonic = "li";
                        sprintf(buf, "$%s, 0x%x", cs_reg_name(handle, rd), addr);
                        insns[search].op_str = buf;
                        insns[search].operands[1].type = MIPS_OP_IMM;
                        insns[search].operands[1].imm = addr;

                        switch (insns[offset].id) {
                            case MIPS_INS_ADDIU:
                                insns[offset].id = MIPS_INS_MOVE;
                                insns[offset].operands[1].type = MIPS_OP_REG;
                                insns[offset].mnemonic = "move";
                                sprintf(buf, "$%s, $%s", cs_reg_name(handle, insns[offset].operands[0].reg),
                                        cs_reg_name(handle, rd));
                                insns[offset].op_str = buf;

                                if (addr >= text_vaddr && addr < text_vaddr + text_section_len) {
                                    add_function(addr);
                                }
                                break;

                            case MIPS_INS_LB:
                            case MIPS_INS_LBU:
                            case MIPS_INS_SB:
                            case MIPS_INS_LH:
                            case MIPS_INS_LHU:
                            case MIPS_INS_SH:
                            case MIPS_INS_LW:
                            case MIPS_INS_SW:
                            case MIPS_INS_LDC1:
                            case MIPS_INS_LWC1:
                            case MIPS_INS_SWC1:
                                insns[offset].operands[1].mem.disp = 0;
                                sprintf(buf, "$%s, ($%s)", cs_reg_name(handle, insns[offset].operands[0].reg),
                                        cs_reg_name(handle, rd));
                                insns[offset].op_str = buf;
                                break;

                            default:
                                assert(0);
                        }
                    }
                    break;
                } else {
                    // ignore: reg is pointer, offset is probably struct data member
                    break;
                }
            }
        } else if (insns[search].id == MIPS_INS_JR && insns[search].operands[0].reg == MIPS_REG_RA &&
                   offset - search >= 2) {
            // stop looking when previous `jr ra` is hit,
            // but ignore if `offset` is branch delay slot for this `jr ra`
            break;
        }
    }
}

// for a given `jalr t9`, find the matching t9 load
static void r_link_with_jalr(int offset) {
    // end search after some sane max number of instructions
    int end_search = std::max(0, offset - MAX_LOOKBACK);

    for (int search = offset - 1; search >= end_search; search--) {
        if (RAB_INSTR_GET_rs(&rinsns[search].instruction) == RABBITIZER_REG_GPR_O32_t9) {
            // should be a switch with returns
            switch (rinsns[search].instruction.uniqueId) {
                case RABBITIZER_INSTR_ID_cpu_lw:
                case RABBITIZER_INSTR_ID_cpu_ori: // LI
                    if (insns[search].is_global_got_memop ||
                        (rinsns[search].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_ori)) {
                        rinsns[search].linked_insn = offset;
                        rinsns[offset].linked_insn = search;
                        rinsns[offset].linked_value = rinsns[search].linked_value;

                        // rinsns[offset].label = rinsns[search].label;
                        // function_entry_points.insert(rinsns[search].linked_value);
                        rinsns[offset].patched = true;
                        rinsns[offset].patched_addr = RAB_INSTR_GET_immediate(&rinsns[offset].instruction);
                        rinsns[offset].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_jal;
                        rinsns[offset].instruction.descriptor =
                            &RabbitizerInstrDescriptor_Descriptors[rinsns[search].instruction.uniqueId];

                        rinsns[search].patched = true;
                        rinsns[search].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_nop;
                        rinsns[search].instruction.descriptor =
                            &RabbitizerInstrDescriptor_Descriptors[rinsns[search].instruction.uniqueId];
                        rinsns[search].is_global_got_memop = false;

                        add_function(insns[search].linked_value);
                    }
                    goto end;

                case RABBITIZER_INSTR_ID_cpu_addiu:
                    if (rinsns[search].linked_insn != -1) {
                        // function_entry_points.insert(insns[search].linked_value);
                        uint32_t first = rinsns[search].linked_insn;

                        // not describing as patched since instruction not edited
                        rinsns[search].linked_insn = offset;
                        rinsns[offset].linked_insn = first;
                        rinsns[offset].linked_value = rinsns[search].linked_value;
                    }
                    goto end;

                    //! @bug repeated case
                    // case RABBITIZER_INSTR_ID_cpu_ori:
                    //     if (rinsns[search].linked_insn != -1) {
                    //         // function_entry_points.insert(rinsns[search].linked_value);
                    //         uint32_t first = rinsns[search].linked_insn;

                    //         rinsns[search].linked_insn = offset;
                    //         rinsns[offset].linked_insn = first;
                    //         rinsns[offset].linked_value = insns[search].linked_value;

                    //         rinsns[search].patched = true;
                    //         rinsns[search].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_nop;
                    //         rinsns[search].instruction.descriptor =
                    //             &RabbitizerInstrDescriptor_Descriptors[rinsns[search].instruction.uniqueId];
                    //     }
                    //     goto end;

                case RABBITIZER_INSTR_ID_cpu_ld:
                case RABBITIZER_INSTR_ID_cpu_addu:
                case RABBITIZER_INSTR_ID_cpu_add:
                case RABBITIZER_INSTR_ID_cpu_sub:
                case RABBITIZER_INSTR_ID_cpu_subu:
                    goto end;

                default:
                    continue;
            }
        } else if ((rinsns[search].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_jr) &&
                   (RAB_INSTR_GET_rs(&rinsns[search].instruction) == RABBITIZER_REG_GPR_O32_ra)) {
            // stop looking when previous `jr ra` is hit
            goto end;
        }
    }
end:;
}

// for a given `jalr t9`, find the matching t9 load
static void link_with_jalr(int offset) {
    // end search after some sane max number of instructions
    int end_search = std::max(0, offset - MAX_LOOKBACK);

    for (int search = offset - 1; search >= end_search; search--) {
        if (insns[search].operands[0].reg == MIPS_REG_T9) {
            // should be a switch with returns
            if (insns[search].id == MIPS_INS_LW || insns[search].id == MIPS_INS_LI) {
                if (insns[search].is_global_got_memop || insns[search].id == MIPS_INS_LI) {
                    char buf[32];

                    sprintf(buf, "0x%x", insns[search].linked_value);
                    insns[search].linked_insn = offset;
                    insns[offset].linked_insn = search;
                    insns[offset].linked_value = insns[search].linked_value;
                    // insns[offset].label = insns[search].label;
                    // function_entry_points.insert(insns[search].linked_value);
                    insns[offset].id = MIPS_INS_JAL;
                    insns[offset].mnemonic = "jal";
                    insns[offset].op_str = buf;
                    insns[offset].operands[0].type = MIPS_OP_IMM;
                    insns[offset].operands[0].imm = insns[search].linked_value;
                    insns[search].id = MIPS_INS_NOP;
                    insns[search].mnemonic = "nop";
                    insns[search].op_str = "";
                    insns[search].is_global_got_memop = false;
                    add_function(insns[search].linked_value);
                }
                break;
            } else if (insns[search].id == MIPS_INS_ADDIU) {
                if (insns[search].linked_insn != -1) {
                    // function_entry_points.insert(insns[search].linked_value);
                    uint32_t first = insns[search].linked_insn;

                    insns[search].linked_insn = offset;
                    insns[offset].linked_insn = first;
                    insns[offset].linked_value = insns[search].linked_value;
                }
                break;
            } else if (insns[search].id == MIPS_INS_LI) {
                if (insns[search].linked_insn != -1) {
                    // function_entry_points.insert(insns[search].linked_value);
                    uint32_t first = insns[search].linked_insn;

                    insns[search].linked_insn = offset;
                    insns[offset].linked_insn = first;
                    insns[offset].linked_value = insns[search].linked_value;
                    insns[search].id = MIPS_INS_NOP;
                    insns[search].mnemonic = "nop";
                    insns[search].op_str = "";
                }
                break;
            } else if (insns[search].id == MIPS_INS_LD || insns[search].id == MIPS_INS_ADDU ||
                       insns[search].id == MIPS_INS_ADD || insns[search].id == MIPS_INS_SUB ||
                       insns[search].id == MIPS_INS_SUBU) {
                break;
            }
        } else if (insns[search].id == MIPS_INS_JR && insns[search].operands[0].reg == MIPS_REG_RA) {
            // stop looking when previous `jr ra` is hit
            break;
        }
    }
}

// TODO: uniformise use of insn vs rinsns[i]
static void r_pass1(void) {
    for (size_t i = 0; i < rinsns.size(); i++) {
        RInsn& insn = rinsns[i];

        // TODO: replace with BAL. Or just fix properly
        if (insn.instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_bgezal &&
            RAB_INSTR_GET_rs(&insn.instruction) == RABBITIZER_REG_GPR_O32_zero) {
            insn.patched = true;
            insn.patched_addr = RAB_INSTR_GET_immediate(&insn.instruction);
            insn.instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_jal;
            insn.instruction.descriptor = &RabbitizerInstrDescriptor_Descriptors[insn.instruction.uniqueId];
        }

        if (insn.instruction.descriptor->isJump) {
            if (insn.instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_jal ||
                insn.instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_j) {
                uint32_t target =
                    insn.patched ? insn.patched_addr : RabbitizerInstruction_getInstrIndexAsVram(&insn.instruction);

                label_addresses.insert(target);
                add_function(target);
            } else if (insn.instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_jr) {
                // sltiu $at, $ty, z
                // sw    $reg, offset($sp)   (very seldom, one or more, usually in func entry)
                // lw    $gp, offset($sp)    (if PIC, and very seldom)
                // beqz  $at, .L
                // some other instruction    (not always)
                // lui   $at, %hi(jtbl)
                // sll   $tx, $ty, 2
                // addu  $at, $at, $tx
                // lw    $tx, %lo(jtbl)($at)
                // nop                       (code compiled with 5.3)
                // addu  $tx, $tx, $gp       (if PIC)
                // jr    $tx

                // IDO 7.1:
                // lw      at,offset(gp)
                // andi    t9,t8,0x3f
                // sll     t9,t9,0x2
                // addu    at,at,t9
                // lw      t9,offset(at)
                // addu    t9,t9,gp
                // jr      t9

                // IDO 5.3:
                // lw      at,offset(gp)
                // andi    t3,t2,0x3f
                // sll     t3,t3,0x2
                // addu    at,at,t3
                // something
                // lw      t3,offset(at)
                // something
                // addu    t3,t3,gp
                // jr      t3
                if (i >= 7 && rodata_section != NULL) {
                    bool is_pic = (rinsns[i - 1].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_addu) &&
                                  (RAB_INSTR_GET_rt(&rinsns[i - 1].instruction) == RABBITIZER_REG_GPR_O32_gp);
                    bool has_nop = rinsns[i - is_pic - 1].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_nop;
                    bool has_extra =
                        rinsns[i - is_pic - has_nop - 5].instruction.uniqueId != RABBITIZER_INSTR_ID_cpu_beqz;
                    int lw = i - (int)is_pic - (int)has_nop - 1;

                    if (rinsns[lw].instruction.uniqueId != RABBITIZER_INSTR_ID_cpu_lw) {
                        --lw;
                    }

                    if ((rinsns[lw].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_lw) &&
                        (rinsns[lw].linked_insn != -1)) {
                        int sltiu_index = -1;
                        int andi_index = -1;
                        uint32_t addu_index = lw - 1;
                        uint32_t num_cases;
                        bool found = false;
                        bool and_variant = false;
                        int end = 14;

                        if (rinsns[addu_index].instruction.uniqueId != RABBITIZER_INSTR_ID_cpu_addu) {
                            --addu_index;
                        }

                        RabbitizerRegister_GprO32 index_reg =
                            (RabbitizerRegister_GprO32)RAB_INSTR_GET_rs(&rinsns[addu_index - 1].instruction);

                        if (rinsns[addu_index].instruction.uniqueId != RABBITIZER_INSTR_ID_cpu_addu) {
                            goto skip;
                        }

                        if (rinsns[addu_index - 1].instruction.uniqueId != RABBITIZER_INSTR_ID_cpu_sll) {
                            goto skip;
                        }

                        if (RAB_INSTR_GET_rs(&rinsns[addu_index - 1].instruction) !=
                            RAB_INSTR_GET_rs(&insn.instruction)) {
                            goto skip;
                        }

                        for (int j = 3; j <= 4; j++) {
                            if (rinsns[lw - j].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_andi) {
                                andi_index = lw - j;
                                break;
                            }
                        }

                        if (i == 368393) {
                            // In copt
                            end = 18;
                        }

                        for (int j = 5; j <= end; j++) {
                            if ((rinsns[lw - has_extra - j].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_sltiu) &&
                                (RAB_INSTR_GET_rs(&rinsns[lw - has_extra - j].instruction) ==
                                 RABBITIZER_REG_GPR_O32_at)) {
                                sltiu_index = j;
                                break;
                            }

                            if (rinsns[lw - has_extra - j].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_jr) {
                                // Prevent going into a previous switch
                                break;
                            }
                        }

                        if (sltiu_index != -1) {
                            andi_index = -1;
                        }

                        if (sltiu_index != -1 && rinsns[lw - has_extra - sltiu_index].instruction.uniqueId ==
                                                     RABBITIZER_INSTR_ID_cpu_sltiu) {
                            num_cases = RAB_INSTR_GET_immediate(&rinsns[lw - has_extra - sltiu_index].instruction);
                            found = true;
                        } else if (andi_index != -1) {
                            num_cases = RAB_INSTR_GET_immediate(&rinsns[andi_index].instruction) + 1;
                            found = true;
                            and_variant = true;
                        } else if (i == 219382) {
                            // Special hard case in copt where the initial sltiu is in another basic block
                            found = true;
                            num_cases = 13;
                        } else if (i == 370995) {
                            // Special hard case in copt where the initial sltiu is in another basic block
                            found = true;
                            num_cases = 12;
                        }

                        if (found) {
                            uint32_t jtbl_addr = rinsns[lw].linked_value;

                            if (is_pic) {
                                rinsns[i - 1].patched = true;
                                rinsns[i - 1].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_nop;
                                rinsns[i - 1].instruction.descriptor =
                                    &RabbitizerInstrDescriptor_Descriptors[rinsns[i - 1].instruction.uniqueId];
                            }

                            // printf("jump table at %08x, size %u\n", jtbl_addr, num_cases);
                            insn.jtbl_addr = jtbl_addr;
                            insn.num_cases = num_cases;
                            insn.index_reg = index_reg;
                            rinsns[lw].patched = true;
                            rinsns[lw].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_nop;
                            rinsns[lw].instruction.descriptor =
                                &RabbitizerInstrDescriptor_Descriptors[rinsns[lw].instruction.uniqueId];

                            rinsns[addu_index].patched = true;
                            rinsns[addu_index].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_nop;
                            rinsns[addu_index].instruction.descriptor =
                                &RabbitizerInstrDescriptor_Descriptors[rinsns[addu_index].instruction.uniqueId];
                            rinsns[addu_index - 1].patched = true;
                            rinsns[addu_index - 1].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_nop;
                            rinsns[addu_index - 1].instruction.descriptor =
                                &RabbitizerInstrDescriptor_Descriptors[rinsns[addu_index - 1].instruction.uniqueId];

                            if (!and_variant) {
                                rinsns[addu_index - 2].patched = true;
                                rinsns[addu_index - 2].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_nop;
                                rinsns[addu_index - 2].instruction.descriptor =
                                    &RabbitizerInstrDescriptor_Descriptors[rinsns[addu_index - 1].instruction.uniqueId];
                            }

                            if (jtbl_addr < rodata_vaddr ||
                                jtbl_addr + num_cases * sizeof(uint32_t) > rodata_vaddr + rodata_section_len) {
                                fprintf(stderr, "jump table outside rodata\n");
                                exit(EXIT_FAILURE);
                            }

                            for (uint32_t i = 0; i < num_cases; i++) {
                                uint32_t target_addr =
                                    read_u32_be(rodata_section + (jtbl_addr - rodata_vaddr) + i * sizeof(uint32_t));

                                target_addr += gp_value;
                                // printf("%08X\n", target_addr);
                                label_addresses.insert(target_addr);
                            }
                        }
                    skip:;
                    }
                }
            } else if (RabbitizerInstrDescriptor_isIType(insn.instruction.descriptor)) {
                // both J-type instructions checked above
                uint32_t target = RAB_INSTR_GET_immediate(&insn.instruction);
                label_addresses.insert(target);
            }
        }

        switch (rinsns[i].instruction.uniqueId) {
            // find floating point LI
            case RABBITIZER_INSTR_ID_cpu_mtc1: {
                RabbitizerRegister_GprO32 rt = (RabbitizerRegister_GprO32)RAB_INSTR_GET_rt(&rinsns[i].instruction);

                for (int s = i - 1; s >= 0; s--) {
                    switch (rinsns[s].instruction.uniqueId) {
                        case RABBITIZER_INSTR_ID_cpu_lui:
                            if (RAB_INSTR_GET_rt(&rinsns[s].instruction) == rt) {
                                float f;
                                uint32_t lui_imm = RAB_INSTR_GET_immediate(&rinsns[s].instruction) << 16;

                                memcpy(&f, &lui_imm, sizeof(f));
                                // link up the LUI with this instruction and the float
                                rinsns[s].linked_insn = i;
                                rinsns[s].linked_float = f;
                                // rewrite LUI instruction to be LI
                                rinsns[s].patched = true;
                                rinsns[s].patched_addr = lui_imm;
                                rinsns[s].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_ori; // LI
                                rinsns[s].instruction.descriptor =
                                    &RabbitizerInstrDescriptor_Descriptors[rinsns[s].instruction.uniqueId];
                            }
                            goto loop_end;

                        case RABBITIZER_INSTR_ID_cpu_lw:
                        case RABBITIZER_INSTR_ID_cpu_ld:
                        case RABBITIZER_INSTR_ID_cpu_lh:
                        case RABBITIZER_INSTR_ID_cpu_lhu:
                        case RABBITIZER_INSTR_ID_cpu_lb:
                        case RABBITIZER_INSTR_ID_cpu_lbu:
                        case RABBITIZER_INSTR_ID_cpu_addiu:
                        case RABBITIZER_INSTR_ID_cpu_add:
                        case RABBITIZER_INSTR_ID_cpu_sub:
                        case RABBITIZER_INSTR_ID_cpu_subu:
                            if (rt == RAB_INSTR_GET_rd(&rinsns[s].instruction)) {
                                goto loop_end;
                            }
                            continue;

                        case RABBITIZER_INSTR_ID_cpu_jr:
                            if (RAB_INSTR_GET_rs(&rinsns[s].instruction) == RABBITIZER_REG_GPR_O32_ra) {
                                goto loop_end;
                            }
                            continue;

                        default:
                            continue;
                    }
                }
            loop_end:;
            } break;

            case RABBITIZER_INSTR_ID_cpu_sd:
            case RABBITIZER_INSTR_ID_cpu_sw:
            case RABBITIZER_INSTR_ID_cpu_sh:
            case RABBITIZER_INSTR_ID_cpu_sb:
            case RABBITIZER_INSTR_ID_cpu_lb:
            case RABBITIZER_INSTR_ID_cpu_lbu:
            case RABBITIZER_INSTR_ID_cpu_ld:
            case RABBITIZER_INSTR_ID_cpu_ldl:
            case RABBITIZER_INSTR_ID_cpu_ldr:
            case RABBITIZER_INSTR_ID_cpu_lh:
            case RABBITIZER_INSTR_ID_cpu_lhu:
            case RABBITIZER_INSTR_ID_cpu_lw:
            case RABBITIZER_INSTR_ID_cpu_lwu:
            case RABBITIZER_INSTR_ID_cpu_ldc1:
            case RABBITIZER_INSTR_ID_cpu_lwc1:
            case RABBITIZER_INSTR_ID_cpu_lwc2:
            // case RABBITIZER_INSTR_ID_cpu_lwc3: // Seems unlikely that this is used
            case RABBITIZER_INSTR_ID_cpu_swc1:
            case RABBITIZER_INSTR_ID_cpu_swc2:
                // case RABBITIZER_INSTR_ID_cpu_swc3:
                {
                    RabbitizerRegister_GprO32 mem_rs =
                        (RabbitizerRegister_GprO32)RAB_INSTR_GET_rs(&rinsns[i].instruction);
                    int mem_imm = (int)RAB_INSTR_GET_immediate(&rinsns[i].instruction);

                    if (mem_rs == RABBITIZER_REG_GPR_O32_gp) {
                        unsigned int got_entry = (mem_imm + gp_value_adj) / sizeof(unsigned int);

                        if (got_entry >= got_locals.size()) {
                            got_entry -= got_locals.size();
                            if (got_entry < got_globals.size()) {
                                assert(insn.instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_lw);
                                // printf("gp 0x%08x %s\n", mem_imm, got_globals[got_entry].name);

                                unsigned int dest_vaddr = got_globals[got_entry];

                                rinsns[i].is_global_got_memop = true;
                                rinsns[i].linked_value = dest_vaddr;
                                // rinsns[i].label = got_globals[got_entry].name;

                                // vaddr_references[dest_vaddr].insert(vaddr + i * 4);
                                // disasm_add_data_addr(state, dest_vaddr);

                                // patch to LI
                                rinsns[i].patched = true;
                                rinsns[i].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_ori; // LI
                                rinsns[i].instruction.descriptor =
                                    &RabbitizerInstrDescriptor_Descriptors[rinsns[i].instruction.uniqueId];
                                rinsns[i].patched_addr = dest_vaddr;
                            }
                        }
                    } else {
                        r_link_with_lui(i, mem_rs, mem_imm);
                    }
                }
                break;

            case RABBITIZER_INSTR_ID_cpu_addiu:
            case RABBITIZER_INSTR_ID_cpu_ori: {
                // could be insn?
                RabbitizerRegister_GprO32 rd = (RabbitizerRegister_GprO32)RAB_INSTR_GET_rd(&rinsns[i].instruction);
                RabbitizerRegister_GprO32 rs = (RabbitizerRegister_GprO32)RAB_INSTR_GET_rs(&rinsns[i].instruction);
                int64_t imm = RAB_INSTR_GET_immediate(&rinsns[i].instruction);

                if (rs == RABBITIZER_REG_GPR_O32_zero) { // becomes LI
                    // char buf[32];

                    // Patch to li?
                    // rinsns[i].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_ori;
                    // rinsns[i].operands[1].imm = imm;
                    // rinsns[i].mnemonic = "li";
                    // sprintf(buf, "$%s, %" PRIi64, cs_reg_name(handle, rd), imm);
                    // rinsns[i].op_str = buf;
                } else if (/*rd == rs &&*/ rd !=
                           RABBITIZER_REG_GPR_O32_gp) { // only look for LUI if rd and rs are the same
                    r_link_with_lui(i, rs, (int)imm);
                }
            } break;

            case RABBITIZER_INSTR_ID_cpu_jalr: {
                RabbitizerRegister_GprO32 rs = (RabbitizerRegister_GprO32)RAB_INSTR_GET_rs(&insn.instruction);

                if (rs == RABBITIZER_REG_GPR_O32_t9) {
                    link_with_jalr(i);
                    if (insn.linked_insn != -1) {
                        insn.patched = true;
                        insn.patched_addr = insn.linked_value;
                        insn.instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_jal;
                        insn.instruction.descriptor = &RabbitizerInstrDescriptor_Descriptors[insn.instruction.uniqueId];

                        label_addresses.insert(insn.linked_value);
                        add_function(insn.linked_value);
                    }
                }
            } break;

            default:
                break;
        }

        if ((insn.instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_addu) &&
            (RAB_INSTR_GET_rd(&insn.instruction) == RABBITIZER_REG_GPR_O32_gp) &&
            (RAB_INSTR_GET_rs(&insn.instruction) == RABBITIZER_REG_GPR_O32_gp) &&
            (RAB_INSTR_GET_rt(&insn.instruction) == RABBITIZER_REG_GPR_O32_t9) && i >= 2) {
            // state->function_entry_points.insert(vaddr + (i - 2) * 4);
            for (size_t j = i - 2; j <= i; j++) {
                rinsns[j].patched = true;
                rinsns[j].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_nop;
                rinsns[j].instruction.descriptor =
                    &RabbitizerInstrDescriptor_Descriptors[rinsns[j].instruction.uniqueId];
            }
        }
    }
}

static void pass1(void) {
    for (size_t i = 0; i < insns.size(); i++) {
        Insn& insn = insns[i];

        if (insn.id == MIPS_INS_BAL) {
            insn.id = MIPS_INS_JAL;
            insn.mnemonic = "jal";
        }

        if (insn.is_jump) {
            if (insn.id == MIPS_INS_JAL || insn.id == MIPS_INS_J) {
                uint32_t target = (uint32_t)insn.operands[0].imm;

                label_addresses.insert(target);
                add_function(target);
            } else if (insn.id == MIPS_INS_JR) {
                // sltiu $at, $ty, z
                // sw    $reg, offset($sp)   (very seldom, one or more, usually in func entry)
                // lw    $gp, offset($sp)    (if PIC, and very seldom)
                // beqz  $at, .L
                // some other instruction    (not always)
                // lui   $at, %hi(jtbl)
                // sll   $tx, $ty, 2
                // addu  $at, $at, $tx
                // lw    $tx, %lo(jtbl)($at)
                // nop                       (code compiled with 5.3)
                // addu  $tx, $tx, $gp       (if PIC)
                // jr    $tx

                // IDO 7.1:
                // lw      at,offset(gp)
                // andi    t9,t8,0x3f
                // sll     t9,t9,0x2
                // addu    at,at,t9
                // lw      t9,offset(at)
                // addu    t9,t9,gp
                // jr      t9

                // IDO 5.3:
                // lw      at,offset(gp)
                // andi    t3,t2,0x3f
                // sll     t3,t3,0x2
                // addu    at,at,t3
                // something
                // lw      t3,offset(at)
                // something
                // addu    t3,t3,gp
                // jr      t3
                if (i >= 7 && rodata_section != NULL) {
                    bool is_pic = insns[i - 1].id == MIPS_INS_ADDU && insns[i - 1].operands[2].reg == MIPS_REG_GP;
                    bool has_nop = insns[i - is_pic - 1].id == MIPS_INS_NOP;
                    bool has_extra = insns[i - is_pic - has_nop - 5].id != MIPS_INS_BEQZ;
                    int lw = i - is_pic - has_nop - 1;

                    if (insns[lw].id != MIPS_INS_LW) {
                        --lw;
                    }

                    if (insns[lw].id == MIPS_INS_LW && insns[lw].linked_insn != -1) {
                        int sltiu_index = -1;
                        int andi_index = -1;
                        uint32_t addu_index = lw - 1;
                        uint32_t num_cases;
                        bool found = false;
                        bool and_variant = false;
                        int end = 14;

                        if (insns[addu_index].id != MIPS_INS_ADDU) {
                            --addu_index;
                        }

                        mips_reg index_reg = (mips_reg)insns[addu_index - 1].operands[1].reg;

                        if (insns[addu_index].id != MIPS_INS_ADDU) {
                            goto skip;
                        }

                        if (insns[addu_index - 1].id != MIPS_INS_SLL) {
                            goto skip;
                        }

                        if (insns[addu_index - 1].operands[0].reg != insn.operands[0].reg) {
                            goto skip;
                        }

                        for (int j = 3; j <= 4; j++) {
                            if (insns[lw - j].id == MIPS_INS_ANDI) {
                                andi_index = lw - j;
                                break;
                            }
                        }

                        if (i == 368393) {
                            // In copt
                            end = 18;
                        }

                        for (int j = 5; j <= end; j++) {
                            if (insns[lw - has_extra - j].id == MIPS_INS_SLTIU &&
                                insns[lw - has_extra - j].operands[0].reg == MIPS_REG_AT) {
                                sltiu_index = j;
                                break;
                            }

                            if (insns[lw - has_extra - j].id == MIPS_INS_JR) {
                                // Prevent going into a previous switch
                                break;
                            }
                        }

                        if (sltiu_index != -1) {
                            andi_index = -1;
                        }

                        if (sltiu_index != -1 && insns[lw - has_extra - sltiu_index].id == MIPS_INS_SLTIU) {
                            num_cases = insns[lw - has_extra - sltiu_index].operands[2].imm;
                            found = true;
                        } else if (andi_index != -1) {
                            num_cases = insns[andi_index].operands[2].imm + 1;
                            found = true;
                            and_variant = true;
                        } else if (i == 219382) {
                            // Special hard case in copt where the initial sltiu is in another basic block
                            found = true;
                            num_cases = 13;
                        } else if (i == 370995) {
                            // Special hard case in copt where the initial sltiu is in another basic block
                            found = true;
                            num_cases = 12;
                        }

                        if (found) {
                            uint32_t jtbl_addr = insns[lw].linked_value;

                            if (is_pic) {
                                insns[i - 1].id = MIPS_INS_NOP;
                            }

                            // printf("jump table at %08x, size %u\n", jtbl_addr, num_cases);
                            insn.jtbl_addr = jtbl_addr;
                            insn.num_cases = num_cases;
                            insn.index_reg = index_reg;
                            insns[lw].id = MIPS_INS_NOP;
                            insns[addu_index].id = MIPS_INS_NOP;
                            insns[addu_index - 1].id = MIPS_INS_NOP;

                            if (!and_variant) {
                                insns[addu_index - 2].id = MIPS_INS_NOP;
                            }

                            if (jtbl_addr < rodata_vaddr ||
                                jtbl_addr + num_cases * sizeof(uint32_t) > rodata_vaddr + rodata_section_len) {
                                fprintf(stderr, "jump table outside rodata\n");
                                exit(EXIT_FAILURE);
                            }

                            for (uint32_t i = 0; i < num_cases; i++) {
                                uint32_t target_addr =
                                    read_u32_be(rodata_section + (jtbl_addr - rodata_vaddr) + i * sizeof(uint32_t));

                                target_addr += gp_value;
                                // printf("%08X\n", target_addr);
                                label_addresses.insert(target_addr);
                            }
                        }
                    skip:;
                    }
                }
            } else {
                for (int j = 0; j < insn.op_count; j++) {
                    if (insn.operands[j].type == MIPS_OP_IMM) {
                        uint32_t target = (uint32_t)insn.operands[j].imm;

                        label_addresses.insert(target);
                    }
                }
            }
        }

        switch (insns[i].id) {
            // find floating point LI
            case MIPS_INS_MTC1: {
                unsigned int rt = insns[i].operands[0].reg;

                for (int s = i - 1; s >= 0; s--) {
                    if (insns[s].id == MIPS_INS_LUI && insns[s].operands[0].reg == rt) {
                        float f;
                        uint32_t lui_imm = (uint32_t)(insns[s].operands[1].imm << 16);

                        memcpy(&f, &lui_imm, sizeof(f));
                        insns[s].operands[1].imm <<= 16;
                        // link up the LUI with this instruction and the float
                        insns[s].linked_insn = i;
                        insns[s].linked_float = f;
                        // rewrite LUI instruction to be LI
                        insns[s].id = MIPS_INS_LI;
                        insns[s].mnemonic = "li";
                        break;
                    } else if (insns[s].id == MIPS_INS_LW || insns[s].id == MIPS_INS_LD || insns[s].id == MIPS_INS_LH ||
                               insns[s].id == MIPS_INS_LHU || insns[s].id == MIPS_INS_LB ||
                               insns[s].id == MIPS_INS_LBU || insns[s].id == MIPS_INS_ADDIU ||
                               insns[s].id == MIPS_INS_ADD || insns[s].id == MIPS_INS_SUB ||
                               insns[s].id == MIPS_INS_SUBU) {
                        unsigned int rd = insns[s].operands[0].reg;
                        if (rt == rd) {
                            break;
                        }
                    } else if (insns[s].id == MIPS_INS_JR && insns[s].operands[0].reg == MIPS_REG_RA) {
                        // stop looking when previous `jr ra` is hit
                        break;
                    }
                }
            } break;

            case MIPS_INS_SD:
            case MIPS_INS_SW:
            case MIPS_INS_SH:
            case MIPS_INS_SB:
            case MIPS_INS_LB:
            case MIPS_INS_LBU:
            case MIPS_INS_LD:
            case MIPS_INS_LDL:
            case MIPS_INS_LDR:
            case MIPS_INS_LH:
            case MIPS_INS_LHU:
            case MIPS_INS_LW:
            case MIPS_INS_LWU:
            case MIPS_INS_LDC1:
            case MIPS_INS_LWC1:
            case MIPS_INS_LWC2:
            case MIPS_INS_LWC3:
            case MIPS_INS_SWC1:
            case MIPS_INS_SWC2:
            case MIPS_INS_SWC3: {
                unsigned int mem_rs = insns[i].operands[1].mem.base;
                int mem_imm = (int)insns[i].operands[1].mem.disp;

                if (mem_rs == MIPS_REG_GP) {
                    unsigned int got_entry = (mem_imm + gp_value_adj) / sizeof(unsigned int);

                    if (got_entry >= got_locals.size()) {
                        got_entry -= got_locals.size();
                        if (got_entry < got_globals.size()) {
                            assert(insn.id == MIPS_INS_LW);
                            // printf("gp 0x%08x %s\n", mem_imm, got_globals[got_entry].name);

                            unsigned int dest_vaddr = got_globals[got_entry];

                            insns[i].is_global_got_memop = true;
                            insns[i].linked_value = dest_vaddr;
                            // insns[i].label = got_globals[got_entry].name;

                            // vaddr_references[dest_vaddr].insert(vaddr + i * 4);
                            // disasm_add_data_addr(state, dest_vaddr);
                            insns[i].id = MIPS_INS_LI;
                            insns[i].operands[1].imm = dest_vaddr;

                            char buf[32];

                            sprintf(buf, "$%s, 0x%x", cs_reg_name(handle, insn.operands[0].reg), dest_vaddr);
                            insns[i].op_str = buf;
                        }
                    }
                } else {
                    link_with_lui(i, mem_rs, mem_imm);
                }
            } break;

            case MIPS_INS_ADDIU:
            case MIPS_INS_ORI: {
                unsigned int rd = insns[i].operands[0].reg;
                unsigned int rs = insns[i].operands[1].reg;
                int64_t imm = insns[i].operands[2].imm;

                if (rs == MIPS_REG_ZERO) { // becomes LI
                    char buf[32];

                    insns[i].id = MIPS_INS_LI;
                    insns[i].operands[1].imm = imm;
                    insns[i].mnemonic = "li";
                    sprintf(buf, "$%s, %" PRIi64, cs_reg_name(handle, rd), imm);
                    insns[i].op_str = buf;
                } else if (/*rd == rs &&*/ rd != MIPS_REG_GP) { // only look for LUI if rd and rs are the same
                    link_with_lui(i, rs, (int)imm);
                }
            } break;

            case MIPS_INS_JALR: {
                unsigned int r = insn.operands[0].reg;

                if (r == MIPS_REG_T9) {
                    link_with_jalr(i);
                    if (insn.linked_insn != -1) {
                        char buf[32];

                        sprintf(buf, "0x%x", insn.linked_value);
                        insn.id = MIPS_INS_JAL;
                        insn.mnemonic = "jal";
                        insn.op_str = buf;
                        insn.operands[0].type = MIPS_OP_IMM;
                        insn.operands[0].imm = insn.linked_value;
                        label_addresses.insert(insn.linked_value);
                        add_function(insn.linked_value);
                    }
                }
            } break;
        }

        if (insn.id == MIPS_INS_ADDU && insn.operands[0].reg == MIPS_REG_GP && insn.operands[1].reg == MIPS_REG_GP &&
            insn.operands[2].reg == MIPS_REG_T9 && i >= 2) {
            // state->function_entry_points.insert(vaddr + (i - 2) * 4);
            for (size_t j = i - 2; j <= i; j++) {
                insns[j].id = MIPS_INS_NOP;
                insns[j].mnemonic = "nop";
                insns[j].op_str = "";
            }
        }
    }
}

static uint32_t addr_to_i(uint32_t addr) {
    return (addr - text_vaddr) / 4;
}

static void r_pass2(void) {
    // Find returns in each function
    for (size_t i = 0; i < rinsns.size(); i++) {
        uint32_t addr = text_vaddr + i * 4;
        RInsn& insn = rinsns[i];

        if ((insn.instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_jr) &&
            (RAB_INSTR_GET_rs(&insn.instruction) == RABBITIZER_REG_GPR_O32_ra)) {
            auto it = find_function(addr);
            assert(it != functions.end());

            it->second.returns.push_back(addr + 4);
        }

        if (insn.is_global_got_memop && (text_vaddr <= RAB_INSTR_GET_immediate(&insn.instruction)) &&
            (RAB_INSTR_GET_immediate(&insn.instruction) < text_vaddr + text_section_len)) {
            uint32_t faddr = RAB_INSTR_GET_immediate(&insn.instruction);

            li_function_pointers.insert(faddr);
            functions[faddr].referenced_by_function_pointer = true;
#if INSPECT_FUNCTION_POINTERS
            fprintf(stderr, "li function pointer: 0x%x at 0x%x\n", faddr, addr);
#endif
        }
    }

    for (auto it = functions.begin(); it != functions.end(); ++it) {
        if (it->second.returns.size() == 0) {
            uint32_t i = addr_to_i(it->first);
            auto str_it = symbol_names.find(it->first);

            if (str_it != symbol_names.end() && str_it->second == "__start") {

            } else if (str_it != symbol_names.end() && str_it->second == "xmalloc") {
                // orig 5.3:
                /*
                496bf4:       3c1c0fb9        lui     gp,0xfb9
                496bf8:       279c366c        addiu   gp,gp,13932
                496bfc:       0399e021        addu    gp,gp,t9
                496c00:       27bdffd8        addiu   sp,sp,-40
                496c04:       8f858de8        lw      a1,-29208(gp)
                496c08:       10000006        b       496c24 <alloc_new+0x14>
                496c0c:       afbf0020        sw      ra,32(sp)
                */

                // jal   alloc_new
                //  lui  $a1, malloc_scb
                // jr    $ra
                //  nop
                uint32_t alloc_new_addr = text_vaddr + (i + 7) * 4;

                // alloc_new
                rinsns[i].patched = true;
                rinsns[i].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_jal;
                rinsns[i].instruction.descriptor =
                    &RabbitizerInstrDescriptor_Descriptors[rinsns[i].instruction.uniqueId];
                rinsns[i].patched_addr = alloc_new_addr;

                assert(symbol_names.count(alloc_new_addr) && symbol_names[alloc_new_addr] == "alloc_new");
                i++;

                // LI
                if ((rinsns[i + 5].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_ori) ||
                    (rinsns[i + 5].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_addiu)) {
                    // 7.1
                    rinsns[i] = rinsns[i + 5];
                } else {
                    // 5.3
                    rinsns[i] = rinsns[i + 3];
                }
                i++;

                // JR $RA
                rinsns[i].patched = true;
                RabbitizerInstruction_init(&rinsns[i].instruction, 0x03E00008, rinsns[i].instruction.vram);
                RabbitizerInstruction_processUniqueId(&rinsns[i].instruction);
                it->second.returns.push_back(text_vaddr + i * 4 + 4);
                i++;

                for (uint32_t j = 0; j < 4; j++) {
                    // NOP
                    rinsns[i].patched = true;
                    RabbitizerInstruction_init(&rinsns[i].instruction, 0, rinsns[i].instruction.vram);
                    RabbitizerInstruction_processUniqueId(&rinsns[i].instruction);
                    i++;
                }
            } else if (str_it != symbol_names.end() && str_it->second == "xfree") {
                // jal   alloc_dispose
                //  lui  $a1, malloc_scb
                // jr    $ra
                //  nop
                uint32_t alloc_dispose_addr = text_vaddr + (i + 4) * 4;

                if (symbol_names.count(alloc_dispose_addr + 4) &&
                    symbol_names[alloc_dispose_addr + 4] == "alloc_dispose") {
                    alloc_dispose_addr += 4;
                }

                // alloc_dispose
                rinsns[i].patched = true;
                rinsns[i].instruction.uniqueId = RABBITIZER_INSTR_ID_cpu_jal;
                rinsns[i].instruction.descriptor =
                    &RabbitizerInstrDescriptor_Descriptors[rinsns[i].instruction.uniqueId];
                rinsns[i].patched_addr = alloc_dispose_addr;
                assert(symbol_names.count(alloc_dispose_addr) && symbol_names[alloc_dispose_addr] == "alloc_dispose");
                i++;

                rinsns[i] = rinsns[i + 2];
                i++;

                // JR $RA
                rinsns[i].patched = true;
                RabbitizerInstruction_init(&rinsns[i].instruction, 0x03E00008, rinsns[i].instruction.vram);
                RabbitizerInstruction_processUniqueId(&rinsns[i].instruction);
                it->second.returns.push_back(text_vaddr + i * 4 + 4);
                i++;

                // NOP
                rinsns[i].patched = true;
                RabbitizerInstruction_init(&rinsns[i].instruction, 0, rinsns[i].instruction.vram);
                RabbitizerInstruction_processUniqueId(&rinsns[i].instruction);
            } else if ((rinsns[i].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_lw) &&
                       (rinsns[i].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_move) &&
                       (rinsns[i].instruction.uniqueId == RABBITIZER_INSTR_ID_cpu_jalr)) {
                /*
                408f50:       8f998010        lw      t9,-32752(gp)
                408f54:       03e07821        move    t7,ra
                408f58:       0320f809        jalr    t9
                */
            } else if (it->first > mcount_addr) {
                fprintf(stderr, "no ret: 0x%x\n", it->first);
                abort();
            }
        }

        auto next = it;

        ++next;
        if (next == functions.end()) {
            it->second.end_addr = text_vaddr + text_section_len;
        } else {
            it->second.end_addr = next->first;
        }
    }
}

static void pass2(void) {
    // Find returns in each function
    for (size_t i = 0; i < insns.size(); i++) {
        uint32_t addr = text_vaddr + i * 4;
        Insn& insn = insns[i];

        if (insn.id == MIPS_INS_JR && insn.operands[0].reg == MIPS_REG_RA) {
            auto it = find_function(addr);
            assert(it != functions.end());

            it->second.returns.push_back(addr + 4);
        }
        if (insn.is_global_got_memop && text_vaddr <= insn.operands[1].imm &&
            insn.operands[1].imm < text_vaddr + text_section_len) {
            uint32_t faddr = insn.operands[1].imm;

            li_function_pointers.insert(faddr);
            functions[faddr].referenced_by_function_pointer = true;
#if INSPECT_FUNCTION_POINTERS
            fprintf(stderr, "li function pointer: 0x%x at 0x%x\n", faddr, addr);
#endif
        }
    }

    for (auto it = functions.begin(); it != functions.end(); ++it) {
        if (it->second.returns.size() == 0) {
            uint32_t i = addr_to_i(it->first);
            auto str_it = symbol_names.find(it->first);

            if (str_it != symbol_names.end() && str_it->second == "__start") {

            } else if (str_it != symbol_names.end() && str_it->second == "xmalloc") {
                // orig 5.3:
                /*
                496bf4:       3c1c0fb9        lui     gp,0xfb9
                496bf8:       279c366c        addiu   gp,gp,13932
                496bfc:       0399e021        addu    gp,gp,t9
                496c00:       27bdffd8        addiu   sp,sp,-40
                496c04:       8f858de8        lw      a1,-29208(gp)
                496c08:       10000006        b       496c24 <alloc_new+0x14>
                496c0c:       afbf0020        sw      ra,32(sp)
                */

                // jal   alloc_new
                //  lui  $a1, malloc_scb
                // jr    $ra
                //  nop
                uint32_t alloc_new_addr = text_vaddr + (i + 7) * 4;

                insns[i].id = MIPS_INS_JAL;
                insns[i].op_count = 1;
                insns[i].mnemonic = "jal";
                insns[i].op_str = "alloc_new";
                insns[i].operands[0].imm = alloc_new_addr;
                assert(symbol_names.count(alloc_new_addr) && symbol_names[alloc_new_addr] == "alloc_new");
                i++;

                if (insns[i + 5].id == MIPS_INS_LI) {
                    // 7.1
                    insns[i] = insns[i + 5];
                } else {
                    // 5.3
                    insns[i] = insns[i + 3];
                }

                i++;
                insns[i].id = MIPS_INS_JR;
                insns[i].op_count = 1;
                insns[i].mnemonic = "jr";
                insns[i].op_str = "$ra";
                insns[i].operands[0].reg = MIPS_REG_RA;
                it->second.returns.push_back(text_vaddr + i * 4 + 4);

                i++;
                for (uint32_t j = 0; j < 4; j++) {
                    insns[i].id = MIPS_INS_NOP;
                    insns[i].op_count = 0;
                    insns[i].mnemonic = "nop";
                    i++;
                }
            } else if (str_it != symbol_names.end() && str_it->second == "xfree") {
                // jal   alloc_dispose
                //  lui  $a1, malloc_scb
                // jr    $ra
                //  nop
                uint32_t alloc_dispose_addr = text_vaddr + (i + 4) * 4;

                if (symbol_names.count(alloc_dispose_addr + 4) &&
                    symbol_names[alloc_dispose_addr + 4] == "alloc_dispose") {
                    alloc_dispose_addr += 4;
                }

                insns[i].id = MIPS_INS_JAL;
                insns[i].op_count = 1;
                insns[i].mnemonic = "jal";
                insns[i].op_str = "alloc_dispose";
                insns[i].operands[0].imm = alloc_dispose_addr;

                assert(symbol_names.count(alloc_dispose_addr) && symbol_names[alloc_dispose_addr] == "alloc_dispose");
                i++;

                insns[i] = insns[i + 2];
                i++;

                insns[i].id = MIPS_INS_JR;
                insns[i].op_count = 1;
                insns[i].mnemonic = "jr";
                insns[i].op_str = "$ra";
                insns[i].operands[0].reg = MIPS_REG_RA;
                it->second.returns.push_back(text_vaddr + i * 4 + 4);
                i++;

                insns[i].id = MIPS_INS_NOP;
                insns[i].op_count = 0;
                insns[i].mnemonic = "nop";
            } else if (insns[i].id == MIPS_INS_LW && insns[i + 1].id == MIPS_INS_MOVE &&
                       insns[i + 2].id == MIPS_INS_JALR) {
                /*
                408f50:       8f998010        lw      t9,-32752(gp)
                408f54:       03e07821        move    t7,ra
                408f58:       0320f809        jalr    t9
                */
            } else if (it->first > mcount_addr) {
                fprintf(stderr, "no ret: 0x%x\n", it->first);
                abort();
            }
        }

        auto next = it;

        ++next;
        if (next == functions.end()) {
            it->second.end_addr = text_vaddr + text_section_len;
        } else {
            it->second.end_addr = next->first;
        }
    }
}

static void add_edge(uint32_t from, uint32_t to, bool function_entry = false, bool function_exit = false,
                     bool extern_function = false, bool function_pointer = false) {
    Edge fe = Edge(), be = Edge();

    fe.i = to;
    be.i = from;
    fe.function_entry = function_entry;
    be.function_entry = function_entry;
    fe.function_exit = function_exit;
    be.function_exit = function_exit;
    fe.extern_function = extern_function;
    be.extern_function = extern_function;
    fe.function_pointer = function_pointer;
    be.function_pointer = function_pointer;
    insns[from].successors.push_back(fe);
    insns[to].predecessors.push_back(be);
}

static void r_pass3(void) {
    // Build graph
    for (size_t i = 0; i < rinsns.size(); i++) {
        uint32_t addr = text_vaddr + i * 4;
        RInsn& insn = rinsns[i];

        if (insn.no_following_successor) {
            continue;
        }

        switch (insn.instruction.uniqueId) {
            case RABBITIZER_INSTR_ID_cpu_beq:
            case RABBITIZER_INSTR_ID_cpu_bgez:
            case RABBITIZER_INSTR_ID_cpu_bgtz:
            case RABBITIZER_INSTR_ID_cpu_blez:
            case RABBITIZER_INSTR_ID_cpu_bltz:
            case RABBITIZER_INSTR_ID_cpu_bne:
            case RABBITIZER_INSTR_ID_cpu_beqz:
            case RABBITIZER_INSTR_ID_cpu_bnez:
            case RABBITIZER_INSTR_ID_cpu_bc1f:
            case RABBITIZER_INSTR_ID_cpu_bc1t:
                add_edge(i, i + 1);
                add_edge(i + 1,
                         addr_to_i(insn.patched ? insn.patched_addr
                                                : (uint32_t)RabbitizerInstruction_getBranchOffset(&insn.instruction)));
                break;

            case RABBITIZER_INSTR_ID_cpu_beql:
            case RABBITIZER_INSTR_ID_cpu_bgezl:
            case RABBITIZER_INSTR_ID_cpu_bgtzl:
            case RABBITIZER_INSTR_ID_cpu_blezl:
            case RABBITIZER_INSTR_ID_cpu_bltzl:
            case RABBITIZER_INSTR_ID_cpu_bnel:
            case RABBITIZER_INSTR_ID_cpu_bc1fl:
            case RABBITIZER_INSTR_ID_cpu_bc1tl:
                add_edge(i, i + 1);
                add_edge(i, i + 2);
                add_edge(i + 1,
                         addr_to_i(insn.patched ? insn.patched_addr
                                                : (uint32_t)RabbitizerInstruction_getBranchOffset(&insn.instruction)));
                rinsns[i + 1].no_following_successor = true; // don't inspect delay slot
                break;

            case RABBITIZER_INSTR_ID_cpu_b:
            case RABBITIZER_INSTR_ID_cpu_j:
                add_edge(i, i + 1);
                add_edge(i + 1,
                         addr_to_i(insn.patched ? insn.patched_addr
                                                : (uint32_t)RabbitizerInstruction_getBranchOffset(&insn.instruction)));
                rinsns[i + 1].no_following_successor = true; // don't inspect delay slot
                break;

            case RABBITIZER_INSTR_ID_cpu_jr: {
                add_edge(i, i + 1);

                if (insn.jtbl_addr != 0) {
                    uint32_t jtbl_pos = insn.jtbl_addr - rodata_vaddr;

                    assert(jtbl_pos < rodata_section_len && jtbl_pos + insn.num_cases * 4 <= rodata_section_len);

                    for (uint32_t j = 0; j < insn.num_cases; j++) {
                        uint32_t dest_addr = read_u32_be(rodata_section + jtbl_pos + j * 4) + gp_value;

                        add_edge(i + 1, addr_to_i(dest_addr));
                    }
                } else {
                    assert(RAB_INSTR_GET_rt(&insn.instruction) == RABBITIZER_REG_GPR_O32_ra &&
                           "jump to address in register not supported");
                }

                rinsns[i + 1].no_following_successor = true; // don't inspect delay slot
                break;
            }

            case RABBITIZER_INSTR_ID_cpu_jal: {
                add_edge(i, i + 1);

                uint32_t dest = RabbitizerInstruction_getInstrIndexAsVram(&insn.instruction);

                if (dest > mcount_addr && dest >= text_vaddr && dest < text_vaddr + text_section_len) {
                    add_edge(i + 1, addr_to_i(dest), true);

                    auto it = functions.find(dest);
                    assert(it != functions.end());

                    for (uint32_t ret_instr : it->second.returns) {
                        add_edge(addr_to_i(ret_instr), i + 2, false, true);
                    }
                } else {
                    add_edge(i + 1, i + 2, false, false, true);
                }

                rinsns[i + 1].no_following_successor = true; // don't inspect delay slot
                break;
            }

            case RABBITIZER_INSTR_ID_cpu_jalr:
                // function pointer
                add_edge(i, i + 1);
                add_edge(i + 1, i + 2, false, false, false, true);
                rinsns[i + 1].no_following_successor = true; // don't inspect delay slot
                break;

            default:
                add_edge(i, i + 1);
                break;
        }
    }
}

static void pass3(void) {
    // Build graph
    for (size_t i = 0; i < insns.size(); i++) {
        uint32_t addr = text_vaddr + i * 4;
        Insn& insn = insns[i];

        if (insn.no_following_successor) {
            continue;
        }

        switch (insn.id) {
            case MIPS_INS_BEQ:
            case MIPS_INS_BGEZ:
            case MIPS_INS_BGTZ:
            case MIPS_INS_BLEZ:
            case MIPS_INS_BLTZ:
            case MIPS_INS_BNE:
            case MIPS_INS_BEQZ:
            case MIPS_INS_BNEZ:
            case MIPS_INS_BC1F:
            case MIPS_INS_BC1T:
                add_edge(i, i + 1);
                add_edge(i + 1, addr_to_i((uint32_t)insn.operands[insn.op_count - 1].imm));
                break;

            case MIPS_INS_BEQL:
            case MIPS_INS_BGEZL:
            case MIPS_INS_BGTZL:
            case MIPS_INS_BLEZL:
            case MIPS_INS_BLTZL:
            case MIPS_INS_BNEL:
            case MIPS_INS_BC1FL:
            case MIPS_INS_BC1TL:
                add_edge(i, i + 1);
                add_edge(i, i + 2);
                add_edge(i + 1, addr_to_i((uint32_t)insn.operands[insn.op_count - 1].imm));
                insns[i + 1].no_following_successor = true; // don't inspect delay slot
                break;

            case MIPS_INS_B:
            case MIPS_INS_J:
                add_edge(i, i + 1);
                add_edge(i + 1, addr_to_i((uint32_t)insn.operands[0].imm));
                insns[i + 1].no_following_successor = true; // don't inspect delay slot
                break;

            case MIPS_INS_JR: {
                add_edge(i, i + 1);

                if (insn.jtbl_addr != 0) {
                    uint32_t jtbl_pos = insn.jtbl_addr - rodata_vaddr;

                    assert(jtbl_pos < rodata_section_len && jtbl_pos + insn.num_cases * 4 <= rodata_section_len);

                    for (uint32_t j = 0; j < insn.num_cases; j++) {
                        uint32_t dest_addr = read_u32_be(rodata_section + jtbl_pos + j * 4) + gp_value;

                        add_edge(i + 1, addr_to_i(dest_addr));
                    }
                } else {
                    assert(insn.operands[0].reg == MIPS_REG_RA && "jump to address in register not supported");
                }

                insns[i + 1].no_following_successor = true; // don't inspect delay slot
                break;
            }

            case MIPS_INS_JAL: {
                add_edge(i, i + 1);

                uint32_t dest = (uint32_t)insn.operands[0].imm;

                if (dest > mcount_addr && dest >= text_vaddr && dest < text_vaddr + text_section_len) {
                    add_edge(i + 1, addr_to_i(dest), true);

                    auto it = functions.find(dest);
                    assert(it != functions.end());

                    for (uint32_t ret_instr : it->second.returns) {
                        add_edge(addr_to_i(ret_instr), i + 2, false, true);
                    }
                } else {
                    add_edge(i + 1, i + 2, false, false, true);
                }

                insns[i + 1].no_following_successor = true; // don't inspect delay slot
                break;
            }

            case MIPS_INS_JALR:
                // function pointer
                add_edge(i, i + 1);
                add_edge(i + 1, i + 2, false, false, false, true);
                insns[i + 1].no_following_successor = true; // don't inspect delay slot
                break;

            default:
                add_edge(i, i + 1);
                break;
        }
    }
}

#define RABBITIZER_REG_GPR_O32_hi (RabbitizerRegister_GprO32)(RABBITIZER_REG_GPR_O32_ra + 1)
#define RABBITIZER_REG_GPR_O32_lo (RabbitizerRegister_GprO32)(RABBITIZER_REG_GPR_O32_ra + 2)

static uint64_t r_map_reg(RabbitizerRegister_GprO32 reg) {
    return (uint64_t)1 << (reg - RABBITIZER_REG_GPR_O32_zero + 1);
}

static uint64_t map_reg(int32_t reg) {
    if (reg > MIPS_REG_31) {
        if (reg == MIPS_REG_HI) {
            reg = MIPS_REG_31 + 1;
        } else if (reg == MIPS_REG_LO) {
            reg = MIPS_REG_31 + 2;
        } else {
            return 0;
        }
    }

    return (uint64_t)1 << (reg - MIPS_REG_0 + 1);
}

static uint64_t r_temporary_regs(void) {
    // clang-format off
    return
        map_reg(RABBITIZER_REG_GPR_O32_t0) |
        map_reg(RABBITIZER_REG_GPR_O32_t1) |
        map_reg(RABBITIZER_REG_GPR_O32_t2) |
        map_reg(RABBITIZER_REG_GPR_O32_t3) |
        map_reg(RABBITIZER_REG_GPR_O32_t4) |
        map_reg(RABBITIZER_REG_GPR_O32_t5) |
        map_reg(RABBITIZER_REG_GPR_O32_t6) |
        map_reg(RABBITIZER_REG_GPR_O32_t7) |
        map_reg(RABBITIZER_REG_GPR_O32_t8) |
        map_reg(RABBITIZER_REG_GPR_O32_t9);
    // clang-format on
}

static uint64_t temporary_regs(void) {
    // clang-format off
    return
        map_reg(MIPS_REG_T0) |
        map_reg(MIPS_REG_T1) |
        map_reg(MIPS_REG_T2) |
        map_reg(MIPS_REG_T3) |
        map_reg(MIPS_REG_T4) |
        map_reg(MIPS_REG_T5) |
        map_reg(MIPS_REG_T6) |
        map_reg(MIPS_REG_T7) |
        map_reg(MIPS_REG_T8) |
        map_reg(MIPS_REG_T9);
    // clang-format on
}

typedef enum {
    TYPE_NOP,        // No arguments
    TYPE_1S,         // 1 in
    TYPE_2S,         // 2 in
    TYPE_1D,         // 1 out
    TYPE_1D_1S,      // 1 out, 1 in
    TYPE_1D_2S,      // 1 out, 2 in
    TYPE_D_LO_HI_2S, // HI/LO out, 2 in
    TYPE_1S_POS1     // ?, 1 in
} TYPE;

static TYPE r_insn_to_type(RInsn& insn) {
    switch (insn.instruction.uniqueId) {

        case RABBITIZER_INSTR_ID_cpu_add_s:
        case RABBITIZER_INSTR_ID_cpu_add_d:
            return TYPE_NOP;
            return TYPE_1D_2S;

        case RABBITIZER_INSTR_ID_cpu_add:
        case RABBITIZER_INSTR_ID_cpu_addu:
        case RABBITIZER_INSTR_ID_cpu_addi:
        case RABBITIZER_INSTR_ID_cpu_addiu:
        case RABBITIZER_INSTR_ID_cpu_andi:
        case RABBITIZER_INSTR_ID_cpu_ori:
        case RABBITIZER_INSTR_ID_cpu_lb:
        case RABBITIZER_INSTR_ID_cpu_lbu:
        case RABBITIZER_INSTR_ID_cpu_lh:
        case RABBITIZER_INSTR_ID_cpu_lhu:
        case RABBITIZER_INSTR_ID_cpu_lw:
        case RABBITIZER_INSTR_ID_cpu_lwl:
        // case RABBITIZER_INSTR_ID_cpu_lwr:
        case RABBITIZER_INSTR_ID_cpu_move:
        case RABBITIZER_INSTR_ID_cpu_negu:
        case RABBITIZER_INSTR_ID_cpu_not:
        case RABBITIZER_INSTR_ID_cpu_sll:
        case RABBITIZER_INSTR_ID_cpu_slti:
        case RABBITIZER_INSTR_ID_cpu_sltiu:
        case RABBITIZER_INSTR_ID_cpu_sra:
        case RABBITIZER_INSTR_ID_cpu_srl:
        case RABBITIZER_INSTR_ID_cpu_xori:
            return TYPE_1D_1S;

        case RABBITIZER_INSTR_ID_cpu_mfhi:
            // TODO: track this properly
            // i.operands[1].reg = MIPS_REG_HI;
            return TYPE_1D_1S;

        case RABBITIZER_INSTR_ID_cpu_mflo:
            // TODO: track this properly
            // i.operands[1].reg = MIPS_REG_LO;
            return TYPE_1D_1S;

        case RABBITIZER_INSTR_ID_cpu_and:
        case RABBITIZER_INSTR_ID_cpu_or:
        case RABBITIZER_INSTR_ID_cpu_nor:
        case RABBITIZER_INSTR_ID_cpu_sllv:
        case RABBITIZER_INSTR_ID_cpu_slt:
        case RABBITIZER_INSTR_ID_cpu_sltu:
        case RABBITIZER_INSTR_ID_cpu_srav:
        case RABBITIZER_INSTR_ID_cpu_srlv:
        case RABBITIZER_INSTR_ID_cpu_subu:
        case RABBITIZER_INSTR_ID_cpu_xor:
            return TYPE_1D_2S;

        case RABBITIZER_INSTR_ID_cpu_cfc1:
        case RABBITIZER_INSTR_ID_cpu_mfc1:
        // case RABBITIZER_INSTR_ID_cpu_li: // LI
        case RABBITIZER_INSTR_ID_cpu_lui:
            return TYPE_1D;

        case RABBITIZER_INSTR_ID_cpu_ctc1:
        case RABBITIZER_INSTR_ID_cpu_bgez:
        case RABBITIZER_INSTR_ID_cpu_bgezl:
        case RABBITIZER_INSTR_ID_cpu_bgtz:
        case RABBITIZER_INSTR_ID_cpu_bgtzl:
        case RABBITIZER_INSTR_ID_cpu_blez:
        case RABBITIZER_INSTR_ID_cpu_blezl:
        case RABBITIZER_INSTR_ID_cpu_bltz:
        case RABBITIZER_INSTR_ID_cpu_bltzl:
        case RABBITIZER_INSTR_ID_cpu_beqz:
        case RABBITIZER_INSTR_ID_cpu_bnez:
        case RABBITIZER_INSTR_ID_cpu_mtc1:
            return TYPE_1S;

        case RABBITIZER_INSTR_ID_cpu_beq:
        case RABBITIZER_INSTR_ID_cpu_beql:
        case RABBITIZER_INSTR_ID_cpu_bne:
        case RABBITIZER_INSTR_ID_cpu_bnel:
        case RABBITIZER_INSTR_ID_cpu_sb:
        case RABBITIZER_INSTR_ID_cpu_sh:
        case RABBITIZER_INSTR_ID_cpu_sw:
        case RABBITIZER_INSTR_ID_cpu_swl:
        // case RABBITIZER_INSTR_ID_cpu_swr:
        case RABBITIZER_INSTR_ID_cpu_tne:
        case RABBITIZER_INSTR_ID_cpu_teq:
        case RABBITIZER_INSTR_ID_cpu_tge:
        case RABBITIZER_INSTR_ID_cpu_tgeu:
        case RABBITIZER_INSTR_ID_cpu_tlt:
            return TYPE_2S;

        case RABBITIZER_INSTR_ID_cpu_div:
            return TYPE_D_LO_HI_2S;

        case RABBITIZER_INSTR_ID_cpu_div_s:
        case RABBITIZER_INSTR_ID_cpu_div_d:
            return TYPE_NOP;

        case RABBITIZER_INSTR_ID_cpu_divu:
        case RABBITIZER_INSTR_ID_cpu_mult:
        case RABBITIZER_INSTR_ID_cpu_multu:
            return TYPE_D_LO_HI_2S;

            // case RABBITIZER_INSTR_ID_cpu_negu: // ? Capstone NEG
            return TYPE_1D_1S;

        case RABBITIZER_INSTR_ID_cpu_neg_s:
        case RABBITIZER_INSTR_ID_cpu_neg_d:
            return TYPE_NOP;

        case RABBITIZER_INSTR_ID_cpu_jalr:
            return TYPE_1S;

        case RABBITIZER_INSTR_ID_cpu_jr:
            if (insn.jtbl_addr != 0) {
                insn.instruction.word = RAB_INSTR_PACK_rs(insn.instruction.word, insn.index_reg);
            }
            if (RAB_INSTR_GET_rt(&insn.instruction) == MIPS_REG_RA) {
                return TYPE_NOP;
            }
            return TYPE_1S;

        case RABBITIZER_INSTR_ID_cpu_lwc1:
        case RABBITIZER_INSTR_ID_cpu_ldc1:
        case RABBITIZER_INSTR_ID_cpu_swc1:
        case RABBITIZER_INSTR_ID_cpu_sdc1:
            return TYPE_1S_POS1;

        default:
            return TYPE_NOP;
    }
}

static TYPE insn_to_type(Insn& i) {
    switch (i.id) {
        case MIPS_INS_ADD:
        case MIPS_INS_ADDU:
            if (i.mnemonic != "add.s" && i.mnemonic != "add.d") {
                return TYPE_1D_2S;
            } else {
                return TYPE_NOP;
            }

        case MIPS_INS_ADDI:
        case MIPS_INS_ADDIU:
        case MIPS_INS_ANDI:
        case MIPS_INS_ORI:
        case MIPS_INS_LB:
        case MIPS_INS_LBU:
        case MIPS_INS_LH:
        case MIPS_INS_LHU:
        case MIPS_INS_LW:
        case MIPS_INS_LWL:
        // case MIPS_INS_LWR:
        case MIPS_INS_MOVE:
        case MIPS_INS_NEGU:
        case MIPS_INS_NOT:
        case MIPS_INS_SLL:
        case MIPS_INS_SLTI:
        case MIPS_INS_SLTIU:
        case MIPS_INS_SRA:
        case MIPS_INS_SRL:
        case MIPS_INS_XORI:
            return TYPE_1D_1S;

        case MIPS_INS_MFHI:
            i.operands[1].reg = MIPS_REG_HI;
            return TYPE_1D_1S;

        case MIPS_INS_MFLO:
            i.operands[1].reg = MIPS_REG_LO;
            return TYPE_1D_1S;

        case MIPS_INS_AND:
        case MIPS_INS_OR:
        case MIPS_INS_NOR:
        case MIPS_INS_SLLV:
        case MIPS_INS_SLT:
        case MIPS_INS_SLTU:
        case MIPS_INS_SRAV:
        case MIPS_INS_SRLV:
        case MIPS_INS_SUBU:
        case MIPS_INS_XOR:
            return TYPE_1D_2S;

        case MIPS_INS_CFC1:
        case MIPS_INS_MFC1:
        case MIPS_INS_LI:
        case MIPS_INS_LUI:
            return TYPE_1D;

        case MIPS_INS_CTC1:
        case MIPS_INS_BGEZ:
        case MIPS_INS_BGEZL:
        case MIPS_INS_BGTZ:
        case MIPS_INS_BGTZL:
        case MIPS_INS_BLEZ:
        case MIPS_INS_BLEZL:
        case MIPS_INS_BLTZ:
        case MIPS_INS_BLTZL:
        case MIPS_INS_BEQZ:
        case MIPS_INS_BNEZ:
        case MIPS_INS_MTC1:
            return TYPE_1S;

        case MIPS_INS_BEQ:
        case MIPS_INS_BEQL:
        case MIPS_INS_BNE:
        case MIPS_INS_BNEL:
        case MIPS_INS_SB:
        case MIPS_INS_SH:
        case MIPS_INS_SW:
        case MIPS_INS_SWL:
        // case MIPS_INS_SWR:
        case MIPS_INS_TNE:
        case MIPS_INS_TEQ:
        case MIPS_INS_TGE:
        case MIPS_INS_TGEU:
        case MIPS_INS_TLT:
            return TYPE_2S;

        case MIPS_INS_DIV:
            if (i.mnemonic != "div.s" && i.mnemonic != "div.d") {
                return TYPE_D_LO_HI_2S;
            } else {
                return TYPE_NOP;
            }

        case MIPS_INS_DIVU:
        case MIPS_INS_MULT:
        case MIPS_INS_MULTU:
            return TYPE_D_LO_HI_2S;

        case MIPS_INS_NEG:
            if (i.mnemonic != "neg.s" && i.mnemonic != "neg.d") {
                return TYPE_1D_1S;
            } else {
                return TYPE_NOP;
            }

        case MIPS_INS_JALR:
            return TYPE_1S;

        case MIPS_INS_JR:
            if (i.jtbl_addr != 0) {
                i.operands[0].reg = i.index_reg;
            }
            if (i.operands[0].reg == MIPS_REG_RA) {
                return TYPE_NOP;
            }
            return TYPE_1S;

        case MIPS_INS_LWC1:
        case MIPS_INS_LDC1:
        case MIPS_INS_SWC1:
        case MIPS_INS_SDC1:
            return TYPE_1S_POS1;

        default:
            return TYPE_NOP;
    }
}

static uint64_t get_dest_reg_mask(const RabbitizerInstruction* instr) {
    if (RabbitizerInstrDescriptor_modifiesRt(instr->descriptor)) {
        return r_map_reg((RabbitizerRegister_GprO32)RAB_INSTR_GET_rt(instr));
    } else if (RabbitizerInstrDescriptor_modifiesRd(instr->descriptor)) {
        return r_map_reg((RabbitizerRegister_GprO32)RAB_INSTR_GET_rd(instr));
    } else {
        assert(!"No destination registers");
    }
}

static uint64_t get_single_source_reg_mask(const RabbitizerInstruction* instr) {
    if (RabbitizerInstruction_hasOperandAlias(instr, RAB_OPERAND_cpu_rs)) {
        return r_map_reg((RabbitizerRegister_GprO32)RAB_INSTR_GET_rs(instr));
    } else if (RabbitizerInstruction_hasOperandAlias(instr, RAB_OPERAND_cpu_rt)) {
        return r_map_reg((RabbitizerRegister_GprO32)RAB_INSTR_GET_rt(instr));
    } else {
        assert(!"No source registers");
    }
}

static uint64_t get_all_source_reg_mask(const RabbitizerInstruction* instr) {
    uint64_t ret = 0;

    if (RabbitizerInstruction_hasOperandAlias(instr, RAB_OPERAND_cpu_rs)) {
        ret |= r_map_reg((RabbitizerRegister_GprO32)RAB_INSTR_GET_rs(instr));
    }
    if (RabbitizerInstruction_hasOperandAlias(instr, RAB_OPERAND_cpu_rt) &&
        !RabbitizerInstrDescriptor_modifiesRt(instr->descriptor)) {
        ret |= r_map_reg((RabbitizerRegister_GprO32)RAB_INSTR_GET_rt(instr));
    }
    return ret;
}

static void r_pass4(void) {
    vector<uint32_t> q; // Why is this called q?
    uint64_t livein_func_start = 1U | r_map_reg(RABBITIZER_REG_GPR_O32_a0) | r_map_reg(RABBITIZER_REG_GPR_O32_a1) |
                                 r_map_reg(RABBITIZER_REG_GPR_O32_sp) | r_map_reg(RABBITIZER_REG_GPR_O32_zero);

    q.push_back(main_addr);
    rinsns[addr_to_i(main_addr)].f_livein = livein_func_start;

    for (auto& it : data_function_pointers) {
        q.push_back(it.second);
        rinsns[addr_to_i(it.second)].f_livein =
            livein_func_start | r_map_reg(RABBITIZER_REG_GPR_O32_a2) | r_map_reg(RABBITIZER_REG_GPR_O32_a3);
    }

    for (auto& addr : li_function_pointers) {
        q.push_back(addr);
        rinsns[addr_to_i(addr)].f_livein =
            livein_func_start | r_map_reg(RABBITIZER_REG_GPR_O32_a2) | r_map_reg(RABBITIZER_REG_GPR_O32_a3);
    }

    while (!q.empty()) {
        uint32_t addr = q.back();
        q.pop_back();
        uint32_t i = addr_to_i(addr);
        RInsn& insn = rinsns[i];
        uint64_t live = insn.f_livein | 1U;
        uint64_t src_regs_map;

        switch (r_insn_to_type(insn)) {
            case TYPE_1D:
                live |= get_dest_reg_mask(&insn.instruction);
                break;

            case TYPE_1D_1S:
                src_regs_map = get_single_source_reg_mask(&insn.instruction);
                if (live & src_regs_map) {
                    live |= get_dest_reg_mask(&insn.instruction);
                }
                break;

            case TYPE_1D_2S:
                src_regs_map = get_all_source_reg_mask(&insn.instruction);
                if ((live & src_regs_map) == src_regs_map) {
                    live |= get_dest_reg_mask(&insn.instruction);
                }
                break;

            case TYPE_D_LO_HI_2S:
                src_regs_map = get_all_source_reg_mask(&insn.instruction);
                if ((live & src_regs_map) == src_regs_map) {
                    live |= r_map_reg(RABBITIZER_REG_GPR_O32_lo);
                    live |= r_map_reg(RABBITIZER_REG_GPR_O32_hi);
                }
                break;

            default:
                break;
        }

        if ((insn.f_liveout | live) == insn.f_liveout) {
            // No new bits
            continue;
        }

        live |= insn.f_liveout;
        insn.f_liveout = live;

        bool function_entry = false;

        for (Edge& e : insn.successors) {
            uint64_t new_live = live;

            if (e.function_exit) {
                new_live &= 1U | r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_v1) |
                            r_map_reg(RABBITIZER_REG_GPR_O32_zero);
            } else if (e.function_entry) {
                new_live &= 1U | r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_a0) |
                            r_map_reg(RABBITIZER_REG_GPR_O32_a1) | r_map_reg(RABBITIZER_REG_GPR_O32_a2) |
                            r_map_reg(RABBITIZER_REG_GPR_O32_a3) | r_map_reg(RABBITIZER_REG_GPR_O32_sp) |
                            r_map_reg(RABBITIZER_REG_GPR_O32_zero);
                function_entry = true;
            } else if (e.extern_function) {
                string_view name;
                // bool is_extern_function = false;
                size_t extern_function_id;
                uint32_t address = insn.patched ? insn.patched_addr
                                                : RabbitizerInstruction_getInstrIndexAsVram(&rinsns[i - 1].instruction);
                // TODO: Can this only ever be a J-type instruction?
                auto it = symbol_names.find(address);
                // auto it = symbol_names.find(rinsns[i - 1].operands[0].imm);
                const ExternFunction* found_fn = nullptr;

                if (it != symbol_names.end()) {
                    name = it->second;

                    for (auto& fn : extern_functions) {
                        if (name == fn.name) {
                            found_fn = &fn;
                            break;
                        }
                    }

                    if (found_fn == nullptr) {
                        fprintf(stderr, "missing extern function: %s\n", string(name).c_str());
                    }
                }

                assert(found_fn);

                char ret_type = found_fn->params[0];

                // if (it != symbol_names.end()) {
                //     name = it->second;

                //     for (size_t i = 0; i < sizeof(extern_functions) / sizeof(extern_functions[0]); i++) {
                //         if (name == extern_functions[i].name) {
                //             is_extern_function = true;
                //             extern_function_id = i;
                //             break;
                //         }
                //     }

                //     if (!is_extern_function) {
                //         fprintf(stderr, "missing extern function: %s\n", name.c_str());
                //     }
                // }

                // assert(is_extern_function);

                // auto& fn = extern_functions[extern_function_id];
                // char ret_type = fn.params[0];

                new_live &=
                    ~(r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_a0) |
                      r_map_reg(RABBITIZER_REG_GPR_O32_a1) | r_map_reg(RABBITIZER_REG_GPR_O32_a2) |
                      r_map_reg(RABBITIZER_REG_GPR_O32_a3) | r_map_reg(RABBITIZER_REG_GPR_O32_v1) | temporary_regs());

                switch (ret_type) {
                    case 'i':
                    case 'u':
                    case 'p':
                        new_live |= r_map_reg(RABBITIZER_REG_GPR_O32_v0);
                        break;

                    case 'f':
                        break;

                    case 'd':
                        break;

                    case 'v':
                        break;

                    case 'l':
                    case 'j':
                        new_live |= r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_v1);
                        break;
                }
            } else if (e.function_pointer) {
                new_live &=
                    ~(r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_a0) |
                      r_map_reg(RABBITIZER_REG_GPR_O32_a1) | r_map_reg(RABBITIZER_REG_GPR_O32_a2) |
                      r_map_reg(RABBITIZER_REG_GPR_O32_a3) | r_map_reg(RABBITIZER_REG_GPR_O32_v1) | temporary_regs());
                new_live |= r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_v1);
            }

            if ((rinsns[e.i].f_livein | new_live) != rinsns[e.i].f_livein) {
                rinsns[e.i].f_livein |= new_live;
                q.push_back(text_vaddr + e.i * sizeof(uint32_t));
            }
        }

        if (function_entry) {
            // add one edge that skips the function call, for callee-saved register liveness propagation
            live &= ~(r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_a0) |
                      r_map_reg(RABBITIZER_REG_GPR_O32_a1) | r_map_reg(RABBITIZER_REG_GPR_O32_a2) |
                      r_map_reg(RABBITIZER_REG_GPR_O32_a3) | r_map_reg(RABBITIZER_REG_GPR_O32_v1) | temporary_regs());

            if ((rinsns[i + 1].f_livein | live) != rinsns[i + 1].f_livein) {
                rinsns[i + 1].f_livein |= live;
                q.push_back(text_vaddr + (i + 1) * sizeof(uint32_t));
            }
        }
    }
}

static void pass4(void) {
    vector<uint32_t> q;
    uint64_t livein_func_start =
        1U | map_reg(MIPS_REG_A0) | map_reg(MIPS_REG_A1) | map_reg(MIPS_REG_SP) | map_reg(MIPS_REG_ZERO);

    q.push_back(main_addr);
    insns[addr_to_i(main_addr)].f_livein = livein_func_start;

    for (auto& it : data_function_pointers) {
        q.push_back(it.second);
        insns[addr_to_i(it.second)].f_livein = livein_func_start | map_reg(MIPS_REG_A2) | map_reg(MIPS_REG_A3);
    }

    for (auto& addr : li_function_pointers) {
        q.push_back(addr);
        insns[addr_to_i(addr)].f_livein = livein_func_start | map_reg(MIPS_REG_A2) | map_reg(MIPS_REG_A3);
    }

    while (!q.empty()) {
        uint32_t addr = q.back();
        q.pop_back();
        uint32_t idx = addr_to_i(addr);
        Insn& i = insns[idx];
        uint64_t live = i.f_livein | 1;

        switch (insn_to_type(i)) {
            case TYPE_1D:
                live |= map_reg(i.operands[0].reg);
                break;

            case TYPE_1D_1S:
                if (live & map_reg(i.operands[1].reg)) {
                    live |= map_reg(i.operands[0].reg);
                }
                break;

            case TYPE_1D_2S:
                if ((live & map_reg(i.operands[1].reg)) && (live & map_reg(i.operands[2].reg))) {
                    live |= map_reg(i.operands[0].reg);
                }
                break;

            case TYPE_D_LO_HI_2S:
                if ((live & map_reg(i.operands[0].reg)) && (live & map_reg(i.operands[1].reg))) {
                    live |= map_reg(MIPS_REG_LO);
                    live |= map_reg(MIPS_REG_HI);
                }
                break;

            default:
                break;
        }

        if ((i.f_liveout | live) == i.f_liveout) {
            // No new bits
            continue;
        }

        live |= i.f_liveout;
        i.f_liveout = live;

        bool function_entry = false;

        for (Edge& e : i.successors) {
            uint64_t new_live = live;

            if (e.function_exit) {
                new_live &= 1U | map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_V1) | map_reg(MIPS_REG_ZERO);
            } else if (e.function_entry) {
                new_live &= 1U | map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_A0) | map_reg(MIPS_REG_A1) |
                            map_reg(MIPS_REG_A2) | map_reg(MIPS_REG_A3) | map_reg(MIPS_REG_SP) | map_reg(MIPS_REG_ZERO);
                function_entry = true;
            } else if (e.extern_function) {
                string name;
                bool is_extern_function = false;
                size_t extern_function_id;
                auto it = symbol_names.find(insns[idx - 1].operands[0].imm);

                if (it != symbol_names.end()) {
                    name = it->second;

                    for (size_t i = 0; i < sizeof(extern_functions) / sizeof(extern_functions[0]); i++) {
                        if (name == extern_functions[i].name) {
                            is_extern_function = true;
                            extern_function_id = i;
                            break;
                        }
                    }

                    if (!is_extern_function) {
                        fprintf(stderr, "missing extern function: %s\n", name.c_str());
                    }
                }

                assert(is_extern_function);

                auto& fn = extern_functions[extern_function_id];
                char ret_type = fn.params[0];

                new_live &= ~(map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_A0) | map_reg(MIPS_REG_A1) |
                              map_reg(MIPS_REG_A2) | map_reg(MIPS_REG_A3) | map_reg(MIPS_REG_V1) | temporary_regs());

                switch (ret_type) {
                    case 'i':
                    case 'u':
                    case 'p':
                        new_live |= map_reg(MIPS_REG_V0);
                        break;

                    case 'f':
                        break;

                    case 'd':
                        break;

                    case 'v':
                        break;

                    case 'l':
                    case 'j':
                        new_live |= map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_V1);
                        break;
                }
            } else if (e.function_pointer) {
                new_live &= ~(map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_A0) | map_reg(MIPS_REG_A1) |
                              map_reg(MIPS_REG_A2) | map_reg(MIPS_REG_A3) | map_reg(MIPS_REG_V1) | temporary_regs());
                new_live |= map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_V1);
            }

            if ((insns[e.i].f_livein | new_live) != insns[e.i].f_livein) {
                insns[e.i].f_livein |= new_live;
                q.push_back(text_vaddr + e.i * 4);
            }
        }

        if (function_entry) {
            // add one edge that skips the function call, for callee-saved register liveness propagation
            live &= ~(map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_A0) | map_reg(MIPS_REG_A1) | map_reg(MIPS_REG_A2) |
                      map_reg(MIPS_REG_A3) | map_reg(MIPS_REG_V1) | temporary_regs());

            if ((insns[idx + 1].f_livein | live) != insns[idx + 1].f_livein) {
                insns[idx + 1].f_livein |= live;
                q.push_back(text_vaddr + (idx + 1) * 4);
            }
        }
    }
}

static void r_pass5(void) {
    vector<uint32_t> q;

    assert(functions.count(main_addr));

    q = functions[main_addr].returns;
    for (auto addr : q) {
        rinsns[addr_to_i(addr)].b_liveout = 1U | r_map_reg(RABBITIZER_REG_GPR_O32_v0);
    }

    for (auto& it : data_function_pointers) {
        for (auto addr : functions[it.second].returns) {
            q.push_back(addr);
            rinsns[addr_to_i(addr)].b_liveout =
                1U | r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_v1);
        }
    }

    for (auto& func_addr : li_function_pointers) {
        for (auto addr : functions[func_addr].returns) {
            q.push_back(addr);
            rinsns[addr_to_i(addr)].b_liveout =
                1U | r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_v1);
        }
    }

    for (size_t i = 0; i < rinsns.size(); i++) {
        if (rinsns[i].f_livein != 0) {
            // Instruction is reachable
            q.push_back(text_vaddr + i * sizeof(uint32_t));
        }
    }

    while (!q.empty()) {
        uint32_t addr = q.back();

        q.pop_back();

        uint32_t i = addr_to_i(addr);
        RInsn& insn = rinsns[i];
        uint64_t live = insn.b_liveout | 1;

        switch (r_insn_to_type(insn)) {
            case TYPE_1S:
                live |= get_single_source_reg_mask(&insn.instruction);
                break;

            case TYPE_1S_POS1:
                live |= get_single_source_reg_mask(&insn.instruction);
                break;

            case TYPE_2S:
                live |= get_all_source_reg_mask(&insn.instruction);
                break;

            case TYPE_1D:
                live &= ~get_dest_reg_mask(&insn.instruction);
                break;

            case TYPE_1D_1S:
                if (live & get_dest_reg_mask(&insn.instruction)) {
                    live &= ~get_dest_reg_mask(&insn.instruction);
                    live |= get_single_source_reg_mask(&insn.instruction);
                }
                break;

            case TYPE_1D_2S:
                if (live & get_dest_reg_mask(&insn.instruction)) {
                    live &= ~get_dest_reg_mask(&insn.instruction);
                    live |= get_all_source_reg_mask(&insn.instruction);
                }
                break;

            case TYPE_D_LO_HI_2S: {
                bool used = (live & (r_map_reg(RABBITIZER_REG_GPR_O32_lo) | r_map_reg(RABBITIZER_REG_GPR_O32_hi)));
                live &= ~(r_map_reg(RABBITIZER_REG_GPR_O32_lo) | r_map_reg(RABBITIZER_REG_GPR_O32_hi));
                if (used) {
                    live |= get_all_source_reg_mask(&insn.instruction);
                }
            } break;

            case TYPE_NOP:
                break;
        }

        if ((insn.b_livein | live) == insn.b_livein) {
            // No new bits
            continue;
        }

        live |= insn.b_livein;
        insn.b_livein = live;

        bool function_exit = false;

        for (Edge& e : insn.predecessors) {
            uint64_t new_live = live;

            if (e.function_exit) {
                new_live &= 1U | r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_v1);
                function_exit = true;
            } else if (e.function_entry) {
                new_live &= 1U | r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_a0) |
                            r_map_reg(RABBITIZER_REG_GPR_O32_a1) | r_map_reg(RABBITIZER_REG_GPR_O32_a2) |
                            r_map_reg(RABBITIZER_REG_GPR_O32_a3) | r_map_reg(RABBITIZER_REG_GPR_O32_sp);
            } else if (e.extern_function) {
                string_view name;
                bool is_extern_function = false;
                size_t extern_function_id;
                const ExternFunction* found_fn = nullptr;
                uint32_t address = insn.patched ? insn.patched_addr
                                                : RabbitizerInstruction_getInstrIndexAsVram(&rinsns[i - 2].instruction);
                // TODO: Can this only ever be a J-type instruction?
                auto it = symbol_names.find(address);

                if (it != symbol_names.end()) {
                    name = it->second;
                    for (auto& fn : extern_functions) {
                        if (name == fn.name) {
                            found_fn = &fn;
                            break;
                        }
                    }
                }

                assert(found_fn);

                uint64_t args = 1U;

                if (found_fn->flags & FLAG_VARARG) {
                    // Assume the worst, that all four registers are used
                    for (int j = 0; j < 4; j++) {
                        args |= r_map_reg((RabbitizerRegister_GprO32)(RABBITIZER_REG_GPR_O32_a0 + j));
                    }
                }

                int pos = 0;
                int pos_float = 0;
                bool only_floats_so_far = true;

                for (const char* p = found_fn->params + 1; *p != '\0'; ++p) {
                    switch (*p) {
                        case 'i':
                        case 'u':
                        case 'p':
                        case 't':
                            only_floats_so_far = false;
                            if (pos < 4) {
                                args |= r_map_reg((RabbitizerRegister_GprO32)(RABBITIZER_REG_GPR_O32_a0 + pos));
                            }
                            ++pos;
                            break;

                        case 'f':
                            if (only_floats_so_far && pos_float < 4) {
                                pos_float += 2;
                            } else if (pos < 4) {
                                args |= r_map_reg((RabbitizerRegister_GprO32)(RABBITIZER_REG_GPR_O32_a0 + pos));
                            }
                            ++pos;
                            break;

                        case 'd':
                            // !!!
                            if (pos % 1 != 0) {
                                ++pos;
                            }
                            if (only_floats_so_far && pos_float < 4) {
                                pos_float += 2;
                            } else if (pos < 4) {
                                args |= r_map_reg((RabbitizerRegister_GprO32)(RABBITIZER_REG_GPR_O32_a0 + pos)) |
                                        r_map_reg((RabbitizerRegister_GprO32)(RABBITIZER_REG_GPR_O32_a0 + pos + 1));
                            }
                            pos += 2;
                            break;

                        case 'l':
                        case 'j':
                            if (pos % 1 != 0) {
                                ++pos;
                            }
                            only_floats_so_far = false;
                            if (pos < 4) {
                                args |= r_map_reg((RabbitizerRegister_GprO32)(RABBITIZER_REG_GPR_O32_a0 + pos)) |
                                        r_map_reg((RabbitizerRegister_GprO32)(RABBITIZER_REG_GPR_O32_a0 + pos + 1));
                            }
                            pos += 2;
                            break;
                    }
                }
                args |= r_map_reg(RABBITIZER_REG_GPR_O32_sp);
                new_live &=
                    ~(r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_a0) |
                      r_map_reg(RABBITIZER_REG_GPR_O32_a1) | r_map_reg(RABBITIZER_REG_GPR_O32_a2) |
                      r_map_reg(RABBITIZER_REG_GPR_O32_a3) | r_map_reg(RABBITIZER_REG_GPR_O32_v1) | temporary_regs());
                new_live |= args;
            } else if (e.function_pointer) {
                new_live &=
                    ~(r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_a0) |
                      r_map_reg(RABBITIZER_REG_GPR_O32_a1) | r_map_reg(RABBITIZER_REG_GPR_O32_a2) |
                      r_map_reg(RABBITIZER_REG_GPR_O32_a3) | r_map_reg(RABBITIZER_REG_GPR_O32_v1) | temporary_regs());
                new_live |= r_map_reg(RABBITIZER_REG_GPR_O32_a0) | r_map_reg(RABBITIZER_REG_GPR_O32_a1) |
                            r_map_reg(RABBITIZER_REG_GPR_O32_a2) | r_map_reg(RABBITIZER_REG_GPR_O32_a3);
            }

            if ((rinsns[e.i].b_liveout | new_live) != rinsns[e.i].b_liveout) {
                rinsns[e.i].b_liveout |= new_live;
                q.push_back(text_vaddr + e.i * sizeof(uint32_t));
            }
        }

        if (function_exit) {
            // add one edge that skips the function call, for callee-saved register liveness propagation
            live &= ~(r_map_reg(RABBITIZER_REG_GPR_O32_v0) | r_map_reg(RABBITIZER_REG_GPR_O32_a0) |
                      r_map_reg(RABBITIZER_REG_GPR_O32_a1) | r_map_reg(RABBITIZER_REG_GPR_O32_a2) |
                      r_map_reg(RABBITIZER_REG_GPR_O32_a3) | r_map_reg(RABBITIZER_REG_GPR_O32_v1) | temporary_regs());

            if ((rinsns[i - 1].b_liveout | live) != rinsns[i - 1].b_liveout) {
                rinsns[i - 1].b_liveout |= live;
                q.push_back(text_vaddr + (i - 1) * sizeof(uint32_t));
            }
        }
    }
}

static void pass5(void) {
    vector<uint32_t> q;

    assert(functions.count(main_addr));

    q = functions[main_addr].returns;
    for (auto addr : q) {
        insns[addr_to_i(addr)].b_liveout = 1U | map_reg(MIPS_REG_V0);
    }

    for (auto& it : data_function_pointers) {
        for (auto addr : functions[it.second].returns) {
            q.push_back(addr);
            insns[addr_to_i(addr)].b_liveout = 1U | map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_V1);
        }
    }

    for (auto& func_addr : li_function_pointers) {
        for (auto addr : functions[func_addr].returns) {
            q.push_back(addr);
            insns[addr_to_i(addr)].b_liveout = 1U | map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_V1);
        }
    }

    for (size_t i = 0; i < insns.size(); i++) {
        if (insns[i].f_livein != 0) {
            // Instruction is reachable
            q.push_back(text_vaddr + i * 4);
        }
    }

    while (!q.empty()) {
        uint32_t addr = q.back();

        q.pop_back();

        uint32_t idx = addr_to_i(addr);
        Insn& i = insns[idx];
        uint64_t live = i.b_liveout | 1;

        switch (insn_to_type(i)) {
            case TYPE_1S:
                live |= map_reg(i.operands[0].reg);
                break;

            case TYPE_1S_POS1:
                live |= map_reg(i.operands[1].reg);
                break;

            case TYPE_2S:
                live |= map_reg(i.operands[0].reg);
                live |= map_reg(i.operands[1].reg);
                break;

            case TYPE_1D:
                live &= ~map_reg(i.operands[0].reg);
                break;

            case TYPE_1D_1S:
                if (live & map_reg(i.operands[0].reg)) {
                    live &= ~map_reg(i.operands[0].reg);
                    live |= map_reg(i.operands[1].reg);
                }
                break;

            case TYPE_1D_2S:
                if (live & map_reg(i.operands[0].reg)) {
                    live &= ~map_reg(i.operands[0].reg);
                    live |= map_reg(i.operands[1].reg);
                    live |= map_reg(i.operands[2].reg);
                }
                break;

            case TYPE_D_LO_HI_2S: {
                bool used = (live & map_reg(MIPS_REG_LO)) || (live & map_reg(MIPS_REG_HI));
                live &= ~map_reg(MIPS_REG_LO);
                live &= ~map_reg(MIPS_REG_HI);
                if (used) {
                    live |= map_reg(i.operands[0].reg);
                    live |= map_reg(i.operands[1].reg);
                }
            } break;

            case TYPE_NOP:
                break;
        }

        if ((i.b_livein | live) == i.b_livein) {
            // No new bits
            continue;
        }

        live |= i.b_livein;
        i.b_livein = live;

        bool function_exit = false;

        for (Edge& e : i.predecessors) {
            uint64_t new_live = live;

            if (e.function_exit) {
                new_live &= 1U | map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_V1);
                function_exit = true;
            } else if (e.function_entry) {
                new_live &= 1U | map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_A0) | map_reg(MIPS_REG_A1) |
                            map_reg(MIPS_REG_A2) | map_reg(MIPS_REG_A3) | map_reg(MIPS_REG_SP);
            } else if (e.extern_function) {
                string name;
                bool is_extern_function = false;
                size_t extern_function_id;
                auto it = symbol_names.find(insns[idx - 2].operands[0].imm);

                if (it != symbol_names.end()) {
                    name = it->second;
                    for (size_t i = 0; i < sizeof(extern_functions) / sizeof(extern_functions[0]); i++) {
                        if (name == extern_functions[i].name) {
                            is_extern_function = true;
                            extern_function_id = i;
                            break;
                        }
                    }
                }

                assert(is_extern_function);

                auto& fn = extern_functions[extern_function_id];
                uint64_t args = 1U;

                if (fn.flags & FLAG_VARARG) {
                    // Assume the worst, that all four registers are used
                    for (int j = 0; j < 4; j++) {
                        args |= map_reg(MIPS_REG_A0 + j);
                    }
                }

                int pos = 0;
                int pos_float = 0;
                bool only_floats_so_far = true;

                for (const char* p = fn.params + 1; *p != '\0'; ++p) {
                    switch (*p) {
                        case 'i':
                        case 'u':
                        case 'p':
                        case 't':
                            only_floats_so_far = false;
                            if (pos < 4) {
                                args |= map_reg(MIPS_REG_A0 + pos);
                            }
                            ++pos;
                            break;

                        case 'f':
                            if (only_floats_so_far && pos_float < 4) {
                                pos_float += 2;
                            } else if (pos < 4) {
                                args |= map_reg(MIPS_REG_A0 + pos);
                            }
                            ++pos;
                            break;

                        case 'd':
                            if (pos % 1 != 0) {
                                ++pos;
                            }
                            if (only_floats_so_far && pos_float < 4) {
                                pos_float += 2;
                            } else if (pos < 4) {
                                args |= map_reg(MIPS_REG_A0 + pos) | map_reg(MIPS_REG_A0 + pos + 1);
                            }
                            pos += 2;
                            break;

                        case 'l':
                        case 'j':
                            if (pos % 1 != 0) {
                                ++pos;
                            }
                            only_floats_so_far = false;
                            if (pos < 4) {
                                args |= map_reg(MIPS_REG_A0 + pos) | map_reg(MIPS_REG_A0 + pos + 1);
                            }
                            pos += 2;
                            break;
                    }
                }
                args |= map_reg(MIPS_REG_SP);
                new_live &= ~(map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_A0) | map_reg(MIPS_REG_A1) |
                              map_reg(MIPS_REG_A2) | map_reg(MIPS_REG_A3) | map_reg(MIPS_REG_V1) | temporary_regs());
                new_live |= args;
            } else if (e.function_pointer) {
                new_live &= ~(map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_A0) | map_reg(MIPS_REG_A1) |
                              map_reg(MIPS_REG_A2) | map_reg(MIPS_REG_A3) | map_reg(MIPS_REG_V1) | temporary_regs());
                new_live |= map_reg(MIPS_REG_A0) | map_reg(MIPS_REG_A1) | map_reg(MIPS_REG_A2) | map_reg(MIPS_REG_A3);
            }

            if ((insns[e.i].b_liveout | new_live) != insns[e.i].b_liveout) {
                insns[e.i].b_liveout |= new_live;
                q.push_back(text_vaddr + e.i * 4);
            }
        }

        if (function_exit) {
            // add one edge that skips the function call, for callee-saved register liveness propagation
            live &= ~(map_reg(MIPS_REG_V0) | map_reg(MIPS_REG_A0) | map_reg(MIPS_REG_A1) | map_reg(MIPS_REG_A2) |
                      map_reg(MIPS_REG_A3) | map_reg(MIPS_REG_V1) | temporary_regs());

            if ((insns[idx - 1].b_liveout | live) != insns[idx - 1].b_liveout) {
                insns[idx - 1].b_liveout |= live;
                q.push_back(text_vaddr + (idx - 1) * 4);
            }
        }
    }
}

static void r_pass6(void) {
    for (auto& it : functions) {
        uint32_t addr = it.first;
        Function& f = it.second;

        for (uint32_t ret : f.returns) {
            RInsn& i = rinsns[addr_to_i(ret)];

            if (i.f_liveout & i.b_liveout & r_map_reg(RABBITIZER_REG_GPR_O32_v1)) {
                f.nret = 2;
            } else if ((i.f_liveout & i.b_liveout & r_map_reg(RABBITIZER_REG_GPR_O32_v0)) && f.nret == 0) {
                f.nret = 1;
            }
        }

        RInsn& insn = rinsns.at(addr_to_i(addr));

        for (int i = 0; i < 4; i++) {
            if (insn.f_livein & insn.b_livein & r_map_reg((RabbitizerRegister_GprO32)(RABBITIZER_REG_GPR_O32_a0 + i))) {
                f.nargs = 1 + i;
            }
        }
        f.v0_in = (insn.f_livein & insn.b_livein & r_map_reg(RABBITIZER_REG_GPR_O32_v0)) != 0 &&
                  !f.referenced_by_function_pointer;
    }
}

static void pass6(void) {
    for (auto& it : functions) {
        uint32_t addr = it.first;
        Function& f = it.second;

        for (uint32_t ret : f.returns) {
            Insn& i = insns[addr_to_i(ret)];

            if (i.f_liveout & i.b_liveout & map_reg(MIPS_REG_V1)) {
                f.nret = 2;
            } else if ((i.f_liveout & i.b_liveout & map_reg(MIPS_REG_V0)) && f.nret == 0) {
                f.nret = 1;
            }
        }

        Insn& insn = insns.at(addr_to_i(addr));

        for (int i = 0; i < 4; i++) {
            if (insn.f_livein & insn.b_livein & map_reg(MIPS_REG_A0 + i)) {
                f.nargs = 1 + i;
            }
        }
        f.v0_in = (insn.f_livein & insn.b_livein & map_reg(MIPS_REG_V0)) != 0 && !f.referenced_by_function_pointer;
    }
}

static void r_dump(void) {
    char buf[0x100] = { 0 };

    for (size_t i = 0; i < rinsns.size(); i++) {
        RInsn& insn = rinsns[i];
        uint32_t vaddr = text_vaddr + i * sizeof(uint32_t);
        if (label_addresses.count(vaddr)) {
            if (symbol_names.count(vaddr)) {
                printf("L%08x: //%s\n", vaddr, symbol_names[vaddr].c_str());
            } else {
                printf("L%08x:\n", vaddr);
            }
        }

        // TODO: construct an immediate override for the instructions
        RabbitizerInstruction_disassemble(&insn.instruction, buf, NULL, 0, 0);
        printf("\t%s", buf);
        if (insn.patched) {
            printf("\t[patched, immediate now 0x%X]", insn.patched_addr);
        }
        printf("\n");
    }
}

static void dump(void) {
    for (size_t i = 0; i < insns.size(); i++) {
        Insn& insn = insns[i];
        uint32_t vaddr = text_vaddr + i * 4;
        if (label_addresses.count(vaddr)) {
            if (symbol_names.count(vaddr)) {
                printf("L%08x: //%s\n", vaddr, symbol_names[vaddr].c_str());
            } else {
                printf("L%08x:\n", vaddr);
            }
        }
        printf("\t%s %s\n", insn.mnemonic.c_str(), insn.op_str.c_str());
    }
}

static const char* r_r(uint32_t reg) {
    static const char* regs[] = {
        /*  */ "zero", "at", "v0", "v1",
        /*  */ "a0",   "a1", "a2", "a3",
        /*  */ "t0",   "t1", "t2", "t3", "t4", "t5", "t6", "t7",
        /*  */ "s0",   "s1", "s2", "s3", "s4", "s5", "s6", "s7",
        /*  */ "t8",   "t9", "k0", "k1", "gp", "sp", "fp", "ra",
    };
    return regs[reg];
}

static const char* r(uint32_t reg) {
    return cs_reg_name(handle, reg);
}

static const char* r_wr(uint32_t reg) {
    // clang-format off
    static const char *regs[] = {
        "f0.w[0]", "f0.w[1]",
        "f2.w[0]", "f2.w[1]",
        "f4.w[0]", "f4.w[1]",
        "f6.w[0]", "f6.w[1]",
        "f8.w[0]", "f8.w[1]",
        "f10.w[0]", "f10.w[1]",
        "f12.w[0]", "f12.w[1]",
        "f14.w[0]", "f14.w[1]",
        "f16.w[0]", "f16.w[1]",
        "f18.w[0]", "f18.w[1]",
        "f20.w[0]", "f20.w[1]",
        "f22.w[0]", "f22.w[1]",
        "f24.w[0]", "f24.w[1]",
        "f26.w[0]", "f26.w[1]",
        "f28.w[0]", "f28.w[1]",
        "f30.w[0]", "f30.w[1]"
    };
    // clang-format on

    return regs[reg - RABBITIZER_REG_COP1_O32_fv0];
}

static const char* wr(uint32_t reg) {
    // clang-format off
    static const char *regs[] = {
        "f0.w[0]", "f0.w[1]",
        "f2.w[0]", "f2.w[1]",
        "f4.w[0]", "f4.w[1]",
        "f6.w[0]", "f6.w[1]",
        "f8.w[0]", "f8.w[1]",
        "f10.w[0]", "f10.w[1]",
        "f12.w[0]", "f12.w[1]",
        "f14.w[0]", "f14.w[1]",
        "f16.w[0]", "f16.w[1]",
        "f18.w[0]", "f18.w[1]",
        "f20.w[0]", "f20.w[1]",
        "f22.w[0]", "f22.w[1]",
        "f24.w[0]", "f24.w[1]",
        "f26.w[0]", "f26.w[1]",
        "f28.w[0]", "f28.w[1]",
        "f30.w[0]", "f30.w[1]"
    };
    // clang-format on

    assert(reg >= MIPS_REG_F0 && reg <= MIPS_REG_F31);
    return regs[reg - MIPS_REG_F0];
}

static const char* r_fr(uint32_t reg) {
    // clang-format off
    static const char *regs[] = {
        "f0.f[0]", "f0.f[1]",
        "f2.f[0]", "f2.f[1]",
        "f4.f[0]", "f4.f[1]",
        "f6.f[0]", "f6.f[1]",
        "f8.f[0]", "f8.f[1]",
        "f10.f[0]", "f10.f[1]",
        "f12.f[0]", "f12.f[1]",
        "f14.f[0]", "f14.f[1]",
        "f16.f[0]", "f16.f[1]",
        "f18.f[0]", "f18.f[1]",
        "f20.f[0]", "f20.f[1]",
        "f22.f[0]", "f22.f[1]",
        "f24.f[0]", "f24.f[1]",
        "f26.f[0]", "f26.f[1]",
        "f28.f[0]", "f28.f[1]",
        "f30.f[0]", "f30.f[1]",
    };
    // clang-format on

    return regs[reg - RABBITIZER_REG_COP1_O32_fv0];
}

static const char* fr(uint32_t reg) {
    // clang-format off
    static const char *regs[] = {
        "f0.f[0]", "f0.f[1]",
        "f2.f[0]", "f2.f[1]",
        "f4.f[0]", "f4.f[1]",
        "f6.f[0]", "f6.f[1]",
        "f8.f[0]", "f8.f[1]",
        "f10.f[0]", "f10.f[1]",
        "f12.f[0]", "f12.f[1]",
        "f14.f[0]", "f14.f[1]",
        "f16.f[0]", "f16.f[1]",
        "f18.f[0]", "f18.f[1]",
        "f20.f[0]", "f20.f[1]",
        "f22.f[0]", "f22.f[1]",
        "f24.f[0]", "f24.f[1]",
        "f26.f[0]", "f26.f[1]",
        "f28.f[0]", "f28.f[1]",
        "f30.f[0]", "f30.f[1]",
    };
    // clang-format on

    assert(reg >= MIPS_REG_F0 && reg <= MIPS_REG_F31);
    return regs[reg - MIPS_REG_F0];
}

static const char* r_dr(uint32_t reg) {
    // clang-format off
    static const char *regs[] = {
        "f0",
        "f2",
        "f4",
        "f6",
        "f8",
        "f10",
        "f12",
        "f14",
        "f16",
        "f18",
        "f20",
        "f22",
        "f24",
        "f26",
        "f28",
        "f30"
    };
    // clang-format on

    assert((reg - RABBITIZER_REG_COP1_O32_fv0) % 2 == 0);
    return regs[(reg - RABBITIZER_REG_COP1_O32_fv0) / 2];
}

static const char* dr(uint32_t reg) {
    // clang-format off
    static const char *regs[] = {
        "f0",
        "f2",
        "f4",
        "f6",
        "f8",
        "f10",
        "f12",
        "f14",
        "f16",
        "f18",
        "f20",
        "f22",
        "f24",
        "f26",
        "f28",
        "f30"
    };
    // clang-format on

    assert(reg >= MIPS_REG_F0 && reg <= MIPS_REG_F31 && (reg - MIPS_REG_F0) % 2 == 0);
    return regs[(reg - MIPS_REG_F0) / 2];
}

static void dump_instr(int i);

static void r_dump_cond_branch(int i, const char* lhs, const char* op, const char* rhs) {
    RInsn& insn = rinsns[i];
    const char* cast1 = "";
    const char* cast2 = "";

    if (strcmp(op, "==") && strcmp(op, "!=")) {
        cast1 = "(int)";
        if (strcmp(rhs, "0")) {
            cast2 = "(int)";
        }
    }
    printf("if (%s%s %s %s%s) {", cast1, lhs, op, cast2, rhs);
    dump_instr(i + 1);

    uint32_t addr = insn.patched ? insn.patched_addr : RAB_INSTR_GET_immediate(&insn.instruction);

    printf("goto L%x;}\n", addr);
}

static void dump_cond_branch(int i, const char* lhs, const char* op, const char* rhs) {
    Insn& insn = insns[i];
    const char* cast1 = "";
    const char* cast2 = "";
    if (strcmp(op, "==") && strcmp(op, "!=")) {
        cast1 = "(int)";
        if (strcmp(rhs, "0")) {
            cast2 = "(int)";
        }
    }
    printf("if (%s%s %s %s%s) {", cast1, lhs, op, cast2, rhs);
    dump_instr(i + 1);
    printf("goto L%x;}\n", (uint32_t)insn.operands[insn.op_count - 1].imm);
}

static void r_dump_cond_branch_likely(int i, const char* lhs, const char* op, const char* rhs) {
    uint32_t target = text_vaddr + (i + 2) * sizeof(uint32_t);

    dump_cond_branch(i, lhs, op, rhs);
    if (!TRACE) {
        printf("else goto L%x;\n", target);
    } else {
        printf("else {printf(\"pc=0x%08x (ignored)\\n\"); goto L%x;}\n", text_vaddr + (i + 1) * sizeof(uint32_t),
               target);
    }
    label_addresses.insert(target);
}

static void dump_cond_branch_likely(int i, const char* lhs, const char* op, const char* rhs) {
    uint32_t target = text_vaddr + (i + 2) * 4;
    dump_cond_branch(i, lhs, op, rhs);
    if (!TRACE) {
        printf("else goto L%x;\n", target);
    } else {
        printf("else {printf(\"pc=0x%08x (ignored)\\n\"); goto L%x;}\n", text_vaddr + (i + 1) * 4, target);
    }
    label_addresses.insert(target);
}

static void r_dump_jal(int i, uint32_t imm) {
    string_view name;
    auto it = symbol_names.find(imm);
    const ExternFunction* found_fn = nullptr;

    // Check for an external function at the address in the immediate. If it does not exist, function is internal
    if (it != symbol_names.end()) {
        name = it->second;
        for (auto& fn : extern_functions) {
            if (name == fn.name) {
                found_fn = &fn;
                break;
            }
        }
    }

    dump_instr(i + 1);

    if (found_fn != nullptr) {
        if (found_fn->flags & FLAG_VARARG) {
            for (int j = 0; j < 4; j++) {
                printf("MEM_U32(sp + %d) = %s;\n", j * 4, r_r(RABBITIZER_REG_GPR_O32_a0 + j));
            }
        }

        const char ret_type = found_fn->params[0];

        switch (ret_type) {
            case 'v':
                break;

            case 'i':
            case 'u':
            case 'p':
                printf("%s = ", r_r(RABBITIZER_REG_GPR_O32_v0));
                break;

            case 'f':
                printf("%s = ", r_fr(RABBITIZER_REG_COP1_O32_fv0));
                break;

            case 'd':
                printf("tempf64 = ");
                break;

            case 'l':
            case 'j':
                printf("temp64 = ");
                break;
        }

        printf("wrapper_%s(", string(name).c_str());

        bool first = true;

        if (!(found_fn->flags & FLAG_NO_MEM)) {
            printf("mem");
            first = false;
        }

        int pos = 0;
        int pos_float = 0;
        bool only_floats_so_far = true;
        bool needs_sp = false;

        for (const char* p = &found_fn->params[1]; *p != '\0'; ++p) {
            if (!first) {
                printf(", ");
            }

            first = false;

            switch (*p) {
                case 't':
                    printf("trampoline, ");
                    needs_sp = true;
                    // fallthrough
                case 'i':
                case 'u':
                case 'p':
                    only_floats_so_far = false;
                    if (pos < 4) {
                        printf("%s", r_r(RABBITIZER_REG_GPR_O32_a0 + pos));
                    } else {
                        printf("MEM_%c32(sp + %d)", *p == 'i' ? 'S' : 'U', pos * 4);
                    }
                    ++pos;
                    break;

                case 'f':
                    if (only_floats_so_far && pos_float < 4) {
                        printf("%s", r_fr(RABBITIZER_REG_COP1_O32_fa0 + pos_float));
                        pos_float += 2;
                    } else if (pos < 4) {
                        printf("BITCAST_U32_TO_F32(%s)", r_r(RABBITIZER_REG_GPR_O32_a0 + pos));
                    } else {
                        printf("BITCAST_U32_TO_F32(MEM_U32(sp + %d))", pos * 4);
                    }
                    ++pos;
                    break;

                case 'd':
                    if (pos % 1 != 0) {
                        ++pos;
                    }
                    if (only_floats_so_far && pos_float < 4) {
                        printf("double_from_FloatReg(%s)", r_dr(RABBITIZER_REG_COP1_O32_fa0 + pos_float));
                        pos_float += 2;
                    } else if (pos < 4) {
                        printf("BITCAST_U64_TO_F64(((uint64_t)%s << 32) | (uint64_t)%s)",
                               r_r(RABBITIZER_REG_GPR_O32_a0 + pos), r_r(RABBITIZER_REG_GPR_O32_a0 + pos + 1));
                    } else {
                        printf("BITCAST_U64_TO_F64(((uint64_t)MEM_U32(sp + %d) << 32) | "
                               "(uint64_t)MEM_U32(sp + "
                               "%d))",
                               pos * 4, (pos + 1) * 4);
                    }
                    pos += 2;
                    break;

                case 'l':
                case 'j':
                    if (pos % 1 != 0) {
                        ++pos;
                    }
                    only_floats_so_far = false;
                    if (*p == 'l') {
                        printf("(int64_t)");
                    }
                    if (pos < 4) {
                        printf("(((uint64_t)%s << 32) | (uint64_t)%s)", r_r(RABBITIZER_REG_GPR_O32_a0 + pos),
                               r_r(RABBITIZER_REG_GPR_O32_a0 + pos + 1));
                    } else {
                        printf("(((uint64_t)MEM_U32(sp + %d) << 32) | (uint64_t)MEM_U32(sp + %d))", pos * 4,
                               (pos + 1) * 4);
                    }
                    pos += 2;
                    break;
            }
        }

        if ((found_fn->flags & FLAG_VARARG) || needs_sp) {
            printf("%s%s", first ? "" : ", ", r_r(RABBITIZER_REG_GPR_O32_sp));
        }

        printf(");\n");

        if (ret_type == 'l' || ret_type == 'j') {
            printf("%s = (uint32_t)(temp64 >> 32);\n", r_r(RABBITIZER_REG_GPR_O32_v0));
            printf("%s = (uint32_t)temp64;\n", r_r(RABBITIZER_REG_GPR_O32_v1));
        } else if (ret_type == 'd') {
            printf("%s = FloatReg_from_double(tempf64);\n", r_dr(RABBITIZER_REG_COP1_O32_fv0));
        }

        if (!name.empty()) {
            // printf("printf(\"%s %%x\\n\", %s);\n", name.c_str(), r_r(RABBITIZER_REG_GPR_O32_a0));
        }
    } else {
        Function& f = functions.find(imm)->second;

        if (f.nret == 1) {
            printf("v0 = ");
        } else if (f.nret == 2) {
            printf("temp64 = ");
        }

        if (!name.empty()) {
            // printf("printf(\"%s %%x\\n\", %s);\n", string(name).c_str(), r_r(RABBITIZER_REG_GPR_O32_a0));
            printf("f_%s", string(name).c_str());
        } else {
            printf("func_%x", imm);
        }

        printf("(mem, sp");

        if (f.v0_in) {
            printf(", %s", r_r(RABBITIZER_REG_GPR_O32_v0));
        }

        for (uint32_t i = 0; i < f.nargs; i++) {
            printf(", %s", r_r(RABBITIZER_REG_GPR_O32_a0 + i));
        }

        printf(");\n");

        if (f.nret == 2) {
            printf("%s = (uint32_t)(temp64 >> 32);\n", r_r(RABBITIZER_REG_GPR_O32_v0));
            printf("%s = (uint32_t)temp64;\n", r_r(RABBITIZER_REG_GPR_O32_v1));
        }
    }

    printf("goto L%x;\n", text_vaddr + (i + 2) * sizeof(uint32_t));
    label_addresses.insert(text_vaddr + (i + 2) * sizeof(uint32_t));
}

static void r_dump_instr(int i) {
    RInsn& insn = rinsns[i];

    const char* symbol_name = NULL;
    if (symbol_names.count(text_vaddr + i * sizeof(uint32_t)) != 0) {
        symbol_name = symbol_names[text_vaddr + i * sizeof(uint32_t)].c_str();
        printf("//%s:\n", symbol_name);
    }

    if (TRACE) {
        printf("++cnt; printf(\"pc=0x%08x%s%s\\n\"); ", text_vaddr + i * sizeof(uint32_t), symbol_name ? " " : "",
               symbol_name ? symbol_name : "");
    }

    uint64_t src_regs_map;
    if (!insn.instruction.descriptor->isJump && !conservative) {
        switch (r_insn_to_type(insn)) {
            case TYPE_1S:
                if (!(insn.f_livein & get_single_source_reg_mask(&insn.instruction))) {
                    printf("// fdead %llx ", (unsigned long long)insn.f_livein);
                }
                break;

            case TYPE_1S_POS1:
                if (!(insn.f_livein & get_single_source_reg_mask(&insn.instruction))) {
                    printf("// fdead %llx ", (unsigned long long)insn.f_livein);
                }
                break;

            case TYPE_2S:
                src_regs_map = src_regs_map = get_all_source_reg_mask(&insn.instruction);
                if (!((insn.f_livein & src_regs_map) == src_regs_map)) {
                    printf("// fdead %llx ", (unsigned long long)insn.f_livein);
                }
                break;

            case TYPE_1D_2S:
                if (!(insn.f_livein & r_map_reg((RabbitizerRegister_GprO32)RAB_INSTR_GET_rt(&insn.instruction)))) {
                    printf("// fdead %llx ", (unsigned long long)insn.f_livein);
                    break;
                }
                // fallthrough
            case TYPE_1D_1S:
                if (!(insn.f_livein & get_single_source_reg_mask(&insn.instruction))) {
                    printf("// fdead %llx ", (unsigned long long)insn.f_livein);
                    break;
                }
                // fallthrough
            case TYPE_1D:
                if (!(insn.b_liveout & get_dest_reg_mask(&insn.instruction))) {
                    printf("// bdead %llx ", (unsigned long long)insn.b_liveout);
                }
                break;

            case TYPE_D_LO_HI_2S:
                src_regs_map = src_regs_map = get_all_source_reg_mask(&insn.instruction);
                if (!((insn.f_livein & src_regs_map) == src_regs_map)) {
                    printf("// fdead %llx ", (unsigned long long)insn.f_livein);
                    break;
                }

                if (!(insn.b_liveout & (r_map_reg(RABBITIZER_REG_GPR_O32_lo) | r_map_reg(RABBITIZER_REG_GPR_O32_hi)))) {
                    printf("// bdead %llx ", (unsigned long long)insn.b_liveout);
                }
                break;

            case TYPE_NOP:
                break;
        }
    }

    uint32_t imm;
    switch (insn.instruction.uniqueId) {
        case RABBITIZER_INSTR_ID_cpu_add:
        case RABBITIZER_INSTR_ID_cpu_addu:
            printf("%s = %s + %s;\n", r_r(RAB_INSTR_GET_rd(&insn.instruction)),
                   r_r(RAB_INSTR_GET_rs(&insn.instruction)), r_r(RAB_INSTR_GET_rt(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_add_s:
            printf("%s = %s + %s;\n", r_fr(RAB_INSTR_GET_fd(&insn.instruction)),
                   r_fr(RAB_INSTR_GET_fs(&insn.instruction)), r_fr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_add_d:
            printf("%s = FloatReg_from_double(double_from_FloatReg(%s) + double_from_FloatReg(%s));\n",
                   r_dr(RAB_INSTR_GET_fd(&insn.instruction)), r_dr(RAB_INSTR_GET_fs(&insn.instruction)),
                   r_dr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_addi:
        case RABBITIZER_INSTR_ID_cpu_addiu:
            imm = insn.patched ? insn.patched_addr : RabbitizerInstruction_getProcessedImmediate(&insn.instruction);
            printf("%s = %s + 0x%x;\n", r_r(RAB_INSTR_GET_rt(&insn.instruction)),
                   r_r(RAB_INSTR_GET_rs(&insn.instruction)), imm);
            break;

        case RABBITIZER_INSTR_ID_cpu_and:
            printf("%s = %s & %s;\n", r_r(RAB_INSTR_GET_rd(&insn.instruction)),
                   r_r(RAB_INSTR_GET_rs(&insn.instruction)), r_r(RAB_INSTR_GET_rt(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_andi:
            imm = insn.patched ? insn.patched_addr : RabbitizerInstruction_getProcessedImmediate(&insn.instruction);
            printf("%s = %s & 0x%x;\n", r_r(RAB_INSTR_GET_rt(&insn.instruction)),
                   r_r(RAB_INSTR_GET_rs(&insn.instruction)), imm);
            break;

        case RABBITIZER_INSTR_ID_cpu_beq:
            dump_cond_branch(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)),
                             "==", r_r(RAB_INSTR_GET_rt(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_beql:
            dump_cond_branch_likely(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)),
                                    "==", r_r(RAB_INSTR_GET_rt(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_bgez:
            dump_cond_branch(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)), ">=", "0");
            break;

        case RABBITIZER_INSTR_ID_cpu_bgezl:
            dump_cond_branch_likely(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)), ">=", "0");
            break;

        case RABBITIZER_INSTR_ID_cpu_bgtz:
            dump_cond_branch(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)), ">", "0");
            break;

        case RABBITIZER_INSTR_ID_cpu_bgtzl:
            dump_cond_branch_likely(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)), ">", "0");
            break;

        case RABBITIZER_INSTR_ID_cpu_blez:
            dump_cond_branch(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)), "<=", "0");
            break;

        case RABBITIZER_INSTR_ID_cpu_blezl:
            dump_cond_branch_likely(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)), "<=", "0");
            break;

        case RABBITIZER_INSTR_ID_cpu_bltz:
            dump_cond_branch(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)), "<", "0");
            break;

        case RABBITIZER_INSTR_ID_cpu_bltzl:
            dump_cond_branch_likely(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)), "<", "0");
            break;

        case RABBITIZER_INSTR_ID_cpu_bne:
            dump_cond_branch(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)),
                             "!=", r_r(RAB_INSTR_GET_rt(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_bnel:
            dump_cond_branch_likely(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)),
                                    "!=", r_r(RAB_INSTR_GET_rt(&insn.instruction)));
            break;

            // // Not emitted by rabbitizer
            // case RABBITIZER_INSTR_ID_cpu_bnezl:
            //     dump_cond_branch_likely(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)),
            //                             "!=", "0");
            //     break;

        case RABBITIZER_INSTR_ID_cpu_break:
            printf("abort();\n");
            break;

        case RABBITIZER_INSTR_ID_cpu_beqz:
            dump_cond_branch(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)), "==", "0");
            break;

            /* case RABBITIZER_INSTR_ID_cpu_beqzl:
                dump_cond_branch_likely(i, r_r(RAB_INSTR_GET_rs(&insn.instruction), "==", "0");
                break; */

        case RABBITIZER_INSTR_ID_cpu_b:
            dump_instr(i + 1);
            imm = insn.patched ? insn.patched_addr : RabbitizerInstruction_getProcessedImmediate(&insn.instruction);
            printf("goto L%x;\n", imm);
            break;

        case RABBITIZER_INSTR_ID_cpu_bc1f:
            printf("if (!cf) {");
            dump_instr(i + 1);
            imm = insn.patched ? insn.patched_addr : RabbitizerInstruction_getProcessedImmediate(&insn.instruction);
            printf("goto L%x;}\n", imm);
            break;

        case RABBITIZER_INSTR_ID_cpu_bc1t:
            printf("if (cf) {");
            dump_instr(i + 1);
            imm = insn.patched ? insn.patched_addr : RabbitizerInstruction_getProcessedImmediate(&insn.instruction);
            printf("goto L%x;}\n", imm);
            break;

        case RABBITIZER_INSTR_ID_cpu_bc1fl: {
            uint32_t target = text_vaddr + (i + 2) * sizeof(uint32_t);
            printf("if (!cf) {");
            dump_instr(i + 1);
            imm = insn.patched ? insn.patched_addr : RabbitizerInstruction_getProcessedImmediate(&insn.instruction);
            printf("goto L%x;}\n", imm);
            if (!TRACE) {
                printf("else goto L%x;\n", target);
            } else {
                printf("else {printf(\"pc=0x%08x (ignored)\\n\"); goto L%x;}\n",
                       text_vaddr + (i + 1) * sizeof(uint32_t), target);
            }
            label_addresses.insert(target);
        } break;

        case RABBITIZER_INSTR_ID_cpu_bc1tl: {
            uint32_t target = text_vaddr + (i + 2) * sizeof(uint32_t);
            printf("if (cf) {");
            dump_instr(i + 1);
            imm = insn.patched ? insn.patched_addr : RabbitizerInstruction_getProcessedImmediate(&insn.instruction);
            printf("goto L%x;}\n", imm);
            if (!TRACE) {
                printf("else goto L%x;\n", target);
            } else {
                printf("else {printf(\"pc=0x%08x (ignored)\\n\"); goto L%x;}\n",
                       text_vaddr + (i + 1) * sizeof(uint32_t), target);
            }
            label_addresses.insert(target);
        } break;

        case RABBITIZER_INSTR_ID_cpu_bnez:
            dump_cond_branch(i, r_r(RAB_INSTR_GET_rs(&insn.instruction)), "!=", "0");
            break;

            // // Rabbitizer does not emit this anyway
            // case RABBITIZER_INSTR_ID_cpu_bnezl:
            //     dump_cond_branch_likely(i, r_r(insn.operands[0].reg), "!=", "0");
            //     break;

        case RABBITIZER_INSTR_ID_cpu_c_lt_s:
            printf("cf = %s < %s;\n", r_fr(RAB_INSTR_GET_fs(&insn.instruction)),
                   r_fr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_c_le_s:
            printf("cf = %s <= %s;\n", r_fr(RAB_INSTR_GET_fs(&insn.instruction)),
                   r_fr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_c_eq_s:
            printf("cf = %s == %s;\n", r_fr(RAB_INSTR_GET_fs(&insn.instruction)),
                   r_fr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_c_lt_d:
            printf("cf = double_from_FloatReg(%s) < double_from_FloatReg(%s);\n",
                   r_dr(RAB_INSTR_GET_fs(&insn.instruction)), r_dr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_c_le_d:
            printf("cf = double_from_FloatReg(%s) <= double_from_FloatReg(%s);\n",
                   r_dr(RAB_INSTR_GET_fs(&insn.instruction)), r_dr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_c_eq_d:
            printf("cf = double_from_FloatReg(%s) == double_from_FloatReg(%s);\n",
                   r_dr(RAB_INSTR_GET_fs(&insn.instruction)), r_dr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_cvt_s_w:
            printf("%s = (int)%s;\n", r_fr(RAB_INSTR_GET_fd(&insn.instruction)),
                   r_wr(RAB_INSTR_GET_fs(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_cvt_d_w:
            printf("%s = FloatReg_from_double((int)%s);\n", r_dr(RAB_INSTR_GET_fd(&insn.instruction)),
                   r_wr(RAB_INSTR_GET_fs(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_cvt_d_s:
            printf("%s = FloatReg_from_double(%s);\n", r_dr(RAB_INSTR_GET_fd(&insn.instruction)),
                   r_fr(RAB_INSTR_GET_fs(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_cvt_s_d:
            printf("%s = double_from_FloatReg(%s);\n", r_fr(RAB_INSTR_GET_fd(&insn.instruction)),
                   r_dr(RAB_INSTR_GET_fs(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_cvt_w_d:
            printf("%s = cvt_w_d(double_from_FloatReg(%s));\n", r_wr(RAB_INSTR_GET_fd(&insn.instruction)),
                   r_dr(RAB_INSTR_GET_fs(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_cvt_w_s:
            printf("%s = cvt_w_s(%s);\n", r_wr(RAB_INSTR_GET_fd(&insn.instruction)),
                   r_fr(RAB_INSTR_GET_fs(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_cvt_l_d:
        case RABBITIZER_INSTR_ID_cpu_cvt_l_s:
        case RABBITIZER_INSTR_ID_cpu_cvt_s_l:
        case RABBITIZER_INSTR_ID_cpu_cvt_d_l:
            goto unimplemented;

        case RABBITIZER_INSTR_ID_cpu_cfc1:
            assert(RAB_INSTR_GET_cop1cs(&insn.instruction) == RABBITIZER_REG_COP1_CONTROL_FpcCsr);
            printf("%s = fcsr;\n", r_r(RAB_INSTR_GET_rt(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_ctc1:
            assert(RAB_INSTR_GET_cop1cs(&insn.instruction) == RABBITIZER_REG_COP1_CONTROL_FpcCsr);
            printf("fcsr = %s;\n", r_r(RAB_INSTR_GET_rt(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_div:
            printf("lo = (int)%s / (int)%s; ", r_r(RAB_INSTR_GET_rs(&insn.instruction)),
                   r_r(RAB_INSTR_GET_rt(&insn.instruction)));
            printf("hi = (int)%s %% (int)%s;\n", r_r(RAB_INSTR_GET_rs(&insn.instruction)),
                   r_r(RAB_INSTR_GET_rt(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_divu:
            printf("lo = %s / %s; ", r_r(RAB_INSTR_GET_rs(&insn.instruction)),
                   r_r(RAB_INSTR_GET_rt(&insn.instruction)));
            printf("hi = %s %% %s;\n", r_r(RAB_INSTR_GET_rs(&insn.instruction)),
                   r_r(RAB_INSTR_GET_rt(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_div_s:
            printf("%s = %s / %s;\n", r_fr(RAB_INSTR_GET_fd(&insn.instruction)),
                   r_fr(RAB_INSTR_GET_fs(&insn.instruction)), r_fr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_div_d:
            printf("%s = FloatReg_from_double(double_from_FloatReg(%s) / double_from_FloatReg(%s));\n",
                   r_dr(RAB_INSTR_GET_fd(&insn.instruction)), r_dr(RAB_INSTR_GET_fs(&insn.instruction)),
                   r_dr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_mov_s:
            printf("%s = %s;\n", r_fr(RAB_INSTR_GET_fd(&insn.instruction)), r_fr(RAB_INSTR_GET_fs(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_mov_d:
            printf("%s = %s;\n", r_dr(RAB_INSTR_GET_fd(&insn.instruction)), r_dr(RAB_INSTR_GET_fs(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_mul_s:
            printf("%s = %s * %s;\n", r_fr(RAB_INSTR_GET_fd(&insn.instruction)),
                   r_fr(RAB_INSTR_GET_fs(&insn.instruction)), r_fr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_mul_d:
            printf("%s = FloatReg_from_double(double_from_FloatReg(%s) * double_from_FloatReg(%s));\n",
                   r_dr(RAB_INSTR_GET_fd(&insn.instruction)), r_dr(RAB_INSTR_GET_fs(&insn.instruction)),
                   r_dr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_negu:
            printf("%s = -%s;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg));
            break;

        case RABBITIZER_INSTR_ID_cpu_neg_s:
            printf("%s = -%s;\n", r_fr(RAB_INSTR_GET_fd(&insn.instruction)), r_fr(RAB_INSTR_GET_fs(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_neg_d:
            printf("%s = FloatReg_from_double(-double_from_FloatReg(%s));\n", r_dr(RAB_INSTR_GET_fd(&insn.instruction)),
                   r_dr(RAB_INSTR_GET_fs(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_sub:
            goto unimplemented;

        case RABBITIZER_INSTR_ID_cpu_sub_s:
            printf("%s = %s - %s;\n", r_fr(RAB_INSTR_GET_fd(&insn.instruction)),
                   r_fr(RAB_INSTR_GET_fs(&insn.instruction)), r_fr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

        case RABBITIZER_INSTR_ID_cpu_sub_d:
            printf("%s = FloatReg_from_double(double_from_FloatReg(%s) - double_from_FloatReg(%s));\n",
                   r_dr(RAB_INSTR_GET_fd(&insn.instruction)), r_dr(RAB_INSTR_GET_fs(&insn.instruction)),
                   r_dr(RAB_INSTR_GET_ft(&insn.instruction)));
            break;

            // Jumps

        case RABBITIZER_INSTR_ID_cpu_j:
            dump_instr(i + 1);
            imm = insn.patched ? insn.patched_addr : RabbitizerInstruction_getProcessedImmediate(&insn.instruction);
            printf("goto L%x;\n", imm);
            break;

        case RABBITIZER_INSTR_ID_cpu_jal:
            // TODO: Seriously consider extracting this into another function
            imm = insn.patched ? insn.patched_addr : RabbitizerInstruction_getProcessedImmediate(&insn.instruction);
            r_dump_jal(i, imm);
            break;

        case MIPS_INS_JALR:
            printf("fp_dest = %s;\n", r_r(insn.operands[0].reg));
            dump_instr(i + 1);
            printf("temp64 = trampoline(mem, sp, %s, %s, %s, %s, fp_dest);\n", r_r(MIPS_REG_A0), r_r(MIPS_REG_A1),
                   r_r(MIPS_REG_A2), r_r(MIPS_REG_A3));
            printf("%s = (uint32_t)(temp64 >> 32);\n", r_r(MIPS_REG_V0));
            printf("%s = (uint32_t)temp64;\n", r_r(MIPS_REG_V1));
            printf("goto L%x;\n", text_vaddr + (i + 2) * 4);
            label_addresses.insert(text_vaddr + (i + 2) * 4);
            break;

        case MIPS_INS_JR:
            if (insn.jtbl_addr != 0) {
                uint32_t jtbl_pos = insn.jtbl_addr - rodata_vaddr;

                assert(jtbl_pos < rodata_section_len && jtbl_pos + insn.num_cases * 4 <= rodata_section_len);
#if 1
                printf(";static void *const Lswitch%x[] = {\n", insn.jtbl_addr);

                for (uint32_t i = 0; i < insn.num_cases; i++) {
                    uint32_t dest_addr = read_u32_be(rodata_section + jtbl_pos + i * 4) + gp_value;
                    printf("&&L%x,\n", dest_addr);
                    label_addresses.insert(dest_addr);
                }

                printf("};\n");
                printf("dest = Lswitch%x[%s];\n", insn.jtbl_addr, r_r(insn.index_reg));
                dump_instr(i + 1);
                printf("goto *dest;\n");
#else
                assert(insns[i + 1].id == MIPS_INS_NOP);
                printf("switch (%s) {\n", r_r(insn.index_reg));

                for (uint32_t i = 0; i < insn.num_cases; i++) {
                    uint32_t dest_addr = read_u32_be(rodata_section + jtbl_pos + i * 4) + gp_value;
                    printf("case %u: goto L%x;\n", i, dest_addr);
                    label_addresses.insert(dest_addr);
                }

                printf("}\n");
#endif
            } else {
                if (insn.operands[0].reg != MIPS_REG_RA) {
                    printf("UNSUPPORTED JR %s %s\n", insn.op_str.c_str(), r_r(insn.operands[0].reg));
                } else {
                    dump_instr(i + 1);
                    switch (find_function(text_vaddr + i * 4)->second.nret) {
                        case 0:
                            printf("return;\n");
                            break;

                        case 1:
                            printf("return v0;\n");
                            break;

                        case 2:
                            printf("return ((uint64_t)v0 << 32) | v1;\n");
                            break;
                    }
                }
            }
            break;

        case MIPS_INS_LB:
            printf("%s = MEM_S8(%s + %d);\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LBU:
            printf("%s = MEM_U8(%s + %d);\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LH:
            printf("%s = MEM_S16(%s + %d);\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LHU:
            printf("%s = MEM_U16(%s + %d);\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LUI:
            printf("%s = 0x%x;\n", r_r(insn.operands[0].reg), ((uint32_t)insn.operands[1].imm) << 16);
            break;

        case MIPS_INS_LW:
            printf("%s = MEM_U32(%s + %d);\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LWC1:
            printf("%s = MEM_U32(%s + %d);\n", r_wr(insn.operands[0].reg), r_r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LDC1:
            assert((insn.operands[0].reg - MIPS_REG_F0) % 2 == 0);
            printf("%s = MEM_U32(%s + %d);\n", r_wr(insn.operands[0].reg + 1), r_r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            printf("%s = MEM_U32(%s + %d + 4);\n", r_wr(insn.operands[0].reg), r_r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LWL: {
            const char* reg = r_r(insn.operands[0].reg);

            printf("%s = %s + %d; ", reg, r_r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp);
            printf("%s = (MEM_U8(%s) << 24) | (MEM_U8(%s + 1) << 16) | (MEM_U8(%s + 2) << 8) | MEM_U8(%s + 3);\n", reg,
                   reg, reg, reg, reg);
        } break;

        case MIPS_INS_LWR:
            printf("//lwr %s\n", insn.op_str.c_str());
            break;

        case MIPS_INS_LI:
            if (insn.is_global_got_memop && text_vaddr <= insn.operands[1].imm &&
                insn.operands[1].imm < text_vaddr + text_section_len) {
                printf("%s = 0x%x; // function pointer\n", r_r(insn.operands[0].reg), (uint32_t)insn.operands[1].imm);
                label_addresses.insert((uint32_t)insn.operands[1].imm);
            } else {
                printf("%s = 0x%x;\n", r_r(insn.operands[0].reg), (uint32_t)insn.operands[1].imm);
            }
            break;

        case MIPS_INS_MFC1:
            printf("%s = %s;\n", r_r(insn.operands[0].reg), r_wr(insn.operands[1].reg));
            break;

        case MIPS_INS_MFHI:
            printf("%s = hi;\n", r_r(insn.operands[0].reg));
            break;

        case MIPS_INS_MFLO:
            printf("%s = lo;\n", r_r(insn.operands[0].reg));
            break;

        case MIPS_INS_MOVE:
            printf("%s = %s;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg));
            break;

        case MIPS_INS_MTC1:
            printf("%s = %s;\n", r_wr(insn.operands[1].reg), r_r(insn.operands[0].reg));
            break;

        case MIPS_INS_MULT:
            printf("lo = %s * %s;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg));
            printf("hi = (uint32_t)((int64_t)(int)%s * (int64_t)(int)%s >> 32);\n", r_r(insn.operands[0].reg),
                   r_r(insn.operands[1].reg));
            break;

        case MIPS_INS_MULTU:
            printf("lo = %s * %s;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg));
            printf("hi = (uint32_t)((uint64_t)%s * (uint64_t)%s >> 32);\n", r_r(insn.operands[0].reg),
                   r_r(insn.operands[1].reg));
            break;

        case MIPS_INS_SQRT:
            printf("%s = sqrtf(%s);\n", r_fr(insn.operands[0].reg), r_fr(insn.operands[1].reg));
            break;

            // case MIPS_INS_FSQRT:
            //     printf("%s = sqrtf(%s);\n", r_wr(insn.operands[0].reg), r_wr(insn.operands[1].reg));
            //     break;

        case MIPS_INS_NEGU:
            printf("%s = -%s;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg));
            break;

        case MIPS_INS_NOR:
            printf("%s = ~(%s | %s);\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   r_r(insn.operands[2].reg));
            break;

        case MIPS_INS_NOT:
            printf("%s = ~%s;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg));
            break;

        case MIPS_INS_OR:
            printf("%s = %s | %s;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg), r_r(insn.operands[2].reg));
            break;

        case MIPS_INS_ORI:
            printf("%s = %s | 0x%x;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_SB:
            printf("MEM_U8(%s + %d) = (uint8_t)%s;\n", r_r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp,
                   r_r(insn.operands[0].reg));
            break;

        case MIPS_INS_SH:
            printf("MEM_U16(%s + %d) = (uint16_t)%s;\n", r_r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp,
                   r_r(insn.operands[0].reg));
            break;

        case MIPS_INS_SLL:
            printf("%s = %s << %d;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_SLLV:
            printf("%s = %s << (%s & 0x1f);\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   r_r(insn.operands[2].reg));
            break;

        case MIPS_INS_SLT:
            printf("%s = (int)%s < (int)%s;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   r_r(insn.operands[2].reg));
            break;

        case MIPS_INS_SLTI:
            printf("%s = (int)%s < (int)0x%x;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_SLTIU:
            printf("%s = %s < 0x%x;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_SLTU:
            printf("%s = %s < %s;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg), r_r(insn.operands[2].reg));
            break;

        case MIPS_INS_SRA:
            printf("%s = (int)%s >> %d;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_SRAV:
            printf("%s = (int)%s >> (%s & 0x1f);\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   r_r(insn.operands[2].reg));
            break;

        case MIPS_INS_SRL:
            printf("%s = %s >> %d;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_SRLV:
            printf("%s = %s >> (%s & 0x1f);\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   r_r(insn.operands[2].reg));
            break;

        case MIPS_INS_SUBU:
            printf("%s = %s - %s;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg), r_r(insn.operands[2].reg));
            break;

        case MIPS_INS_SW:
            printf("MEM_U32(%s + %d) = %s;\n", r_r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp,
                   r_r(insn.operands[0].reg));
            break;

        case MIPS_INS_SWC1:
            printf("MEM_U32(%s + %d) = %s;\n", r_r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp,
                   r_wr(insn.operands[0].reg));
            break;

        case MIPS_INS_SDC1:
            assert((insn.operands[0].reg - MIPS_REG_F0) % 2 == 0);
            printf("MEM_U32(%s + %d) = %s;\n", r_r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp,
                   r_wr(insn.operands[0].reg + 1));
            printf("MEM_U32(%s + %d + 4) = %s;\n", r_r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp,
                   r_wr(insn.operands[0].reg));
            break;

        case MIPS_INS_SWL:
            for (int i = 0; i < 4; i++) {
                printf("MEM_U8(%s + %d + %d) = (uint8_t)(%s >> %d);\n", r_r(insn.operands[1].mem.base),
                       (int)insn.operands[1].mem.disp, i, r_r(insn.operands[0].reg), (3 - i) * 8);
            }
            break;

        case MIPS_INS_SWR:
            printf("//swr %s\n", insn.op_str.c_str());
            break;

        case MIPS_INS_TRUNC:
            if (insn.mnemonic == "trunc.w.s") {
                printf("%s = (int)%s;\n", r_wr(insn.operands[0].reg), r_fr(insn.operands[1].reg));
            } else if (insn.mnemonic == "trunc.w.d") {
                printf("%s = (int)double_from_FloatReg(%s);\n", r_wr(insn.operands[0].reg), r_dr(insn.operands[1].reg));
            } else {
                goto unimplemented;
            }
            break;

        case MIPS_INS_XOR:
            printf("%s = %s ^ %s;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg), r_r(insn.operands[2].reg));
            break;

        case MIPS_INS_XORI:
            printf("%s = %s ^ 0x%x;\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_TNE:
            printf("assert(%s == %s && \"tne %d\");\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   (int)insn.operands[2].imm);
            break;

        case MIPS_INS_TEQ:
            printf("assert(%s != %s && \"teq %d\");\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   (int)insn.operands[2].imm);
            break;

        case MIPS_INS_TGE:
            printf("assert((int)%s < (int)%s && \"tge %d\");\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   (int)insn.operands[2].imm);
            break;

        case MIPS_INS_TGEU:
            printf("assert(%s < %s && \"tgeu %d\");\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   (int)insn.operands[2].imm);
            break;

        case MIPS_INS_TLT:
            printf("assert((int)%s >= (int)%s && \"tlt %d\");\n", r_r(insn.operands[0].reg), r_r(insn.operands[1].reg),
                   (int)insn.operands[2].imm);
            break;

        case MIPS_INS_NOP:
            printf("//nop;\n");
            break;

        default:
        unimplemented:
            printf("UNIMPLEMENTED %s %s\n", insn.mnemonic.c_str(), insn.op_str.c_str());
            break;
    }
}

static void dump_instr(int i) {
    const char* symbol_name = NULL;
    if (symbol_names.count(text_vaddr + i * 4) != 0) {
        symbol_name = symbol_names[text_vaddr + i * 4].c_str();
        printf("//%s:\n", symbol_name);
    }
    if (TRACE) {
        printf("++cnt; printf(\"pc=0x%08x%s%s\\n\"); ", text_vaddr + i * 4, symbol_name ? " " : "",
               symbol_name ? symbol_name : "");
    }
    Insn& insn = insns[i];
    if (!insn.is_jump && !conservative) {
        switch (insn_to_type(insn)) {
            case TYPE_1S:
                if (!(insn.f_livein & map_reg(insn.operands[0].reg))) {
                    printf("// fdead %llx ", (unsigned long long)insn.f_livein);
                }
                break;

            case TYPE_1S_POS1:
                if (!(insn.f_livein & map_reg(insn.operands[1].reg))) {
                    printf("// fdead %llx ", (unsigned long long)insn.f_livein);
                }
                break;

            case TYPE_2S:
                if (!(insn.f_livein & map_reg(insn.operands[0].reg)) ||
                    !(insn.f_livein & map_reg(insn.operands[1].reg))) {
                    printf("// fdead %llx ", (unsigned long long)insn.f_livein);
                }
                break;

            case TYPE_1D_2S:
                if (!(insn.f_livein & map_reg(insn.operands[2].reg))) {
                    printf("// fdead %llx ", (unsigned long long)insn.f_livein);
                    break;
                }
                // fallthrough
            case TYPE_1D_1S:
                if (!(insn.f_livein & map_reg(insn.operands[1].reg))) {
                    printf("// fdead %llx ", (unsigned long long)insn.f_livein);
                    break;
                }
                // fallthrough
            case TYPE_1D:
                if (!(insn.b_liveout & map_reg(insn.operands[0].reg))) {
                    printf("// bdead %llx ", (unsigned long long)insn.b_liveout);
                }
                break;

            case TYPE_D_LO_HI_2S:
                if (!(insn.f_livein & map_reg(insn.operands[0].reg)) ||
                    !(insn.f_livein & map_reg(insn.operands[1].reg))) {
                    printf("// fdead %llx ", (unsigned long long)insn.f_livein);
                    break;
                }

                if (!(insn.b_liveout & (map_reg(MIPS_REG_LO) | map_reg(MIPS_REG_HI)))) {
                    printf("// bdead %llx ", (unsigned long long)insn.b_liveout);
                }
                break;

            case TYPE_NOP:
                break;
        }
    }
    switch (insn.id) {
        case MIPS_INS_ADD:
        case MIPS_INS_ADDU:
            if (insn.mnemonic == "add.s") {
                printf("%s = %s + %s;\n", fr(insn.operands[0].reg), fr(insn.operands[1].reg), fr(insn.operands[2].reg));
            } else if (insn.mnemonic == "add.d") {
                printf("%s = FloatReg_from_double(double_from_FloatReg(%s) + double_from_FloatReg(%s));\n",
                       dr(insn.operands[0].reg), dr(insn.operands[1].reg), dr(insn.operands[2].reg));
            } else {
                printf("%s = %s + %s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg), r(insn.operands[2].reg));
            }
            break;

        case MIPS_INS_ADDI:
        case MIPS_INS_ADDIU:
            printf("%s = %s + 0x%x;\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_AND:
            printf("%s = %s & %s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg), r(insn.operands[2].reg));
            break;

        case MIPS_INS_ANDI:
            printf("%s = %s & 0x%x;\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_BEQ:
            dump_cond_branch(i, r(insn.operands[0].reg), "==", r(insn.operands[1].reg));
            break;

        case MIPS_INS_BEQL:
            dump_cond_branch_likely(i, r(insn.operands[0].reg), "==", r(insn.operands[1].reg));
            break;

        case MIPS_INS_BGEZ:
            dump_cond_branch(i, r(insn.operands[0].reg), ">=", "0");
            break;

        case MIPS_INS_BGEZL:
            dump_cond_branch_likely(i, r(insn.operands[0].reg), ">=", "0");
            break;

        case MIPS_INS_BGTZ:
            dump_cond_branch(i, r(insn.operands[0].reg), ">", "0");
            break;

        case MIPS_INS_BGTZL:
            dump_cond_branch_likely(i, r(insn.operands[0].reg), ">", "0");
            break;

        case MIPS_INS_BLEZ:
            dump_cond_branch(i, r(insn.operands[0].reg), "<=", "0");
            break;

        case MIPS_INS_BLEZL:
            dump_cond_branch_likely(i, r(insn.operands[0].reg), "<=", "0");
            break;

        case MIPS_INS_BLTZ:
            dump_cond_branch(i, r(insn.operands[0].reg), "<", "0");
            break;

        case MIPS_INS_BLTZL:
            dump_cond_branch_likely(i, r(insn.operands[0].reg), "<", "0");
            break;

        case MIPS_INS_BNE:
            dump_cond_branch(i, r(insn.operands[0].reg), "!=", r(insn.operands[1].reg));
            break;

        case MIPS_INS_BNEL:
            dump_cond_branch_likely(i, r(insn.operands[0].reg),
                                    "!=", insn.mnemonic == "bnezl" ? "0" : r(insn.operands[1].reg));
            break;

        case MIPS_INS_BREAK:
            printf("abort();\n");
            break;

        case MIPS_INS_BEQZ:
            dump_cond_branch(i, r(insn.operands[0].reg), "==", "0");
            break;

            /* case MIPS_INS_BEQZL:
                dump_cond_branch_likely(i, r(insn.operands[0].reg), "==", "0");
                break; */

        case MIPS_INS_B:
            dump_instr(i + 1);
            printf("goto L%x;\n", (int32_t)insn.operands[0].imm);
            break;

        case MIPS_INS_BC1F:
        case MIPS_INS_BC1T:
            printf("if (%scf) {", insn.id == MIPS_INS_BC1F ? "!" : "");
            dump_instr(i + 1);
            printf("goto L%x;}\n", (int32_t)insn.operands[0].imm);
            break;

        case MIPS_INS_BC1FL:
        case MIPS_INS_BC1TL: {
            uint32_t target = text_vaddr + (i + 2) * 4;
            printf("if (%scf) {", insn.id == MIPS_INS_BC1FL ? "!" : "");
            dump_instr(i + 1);
            printf("goto L%x;}\n", (int32_t)insn.operands[0].imm);
            if (!TRACE) {
                printf("else goto L%x;\n", target);
            } else {
                printf("else {printf(\"pc=0x%08x (ignored)\\n\"); goto L%x;}\n", text_vaddr + (i + 1) * 4, target);
            }
            label_addresses.insert(target);
        } break;

        case MIPS_INS_BNEZ:
            dump_cond_branch(i, r(insn.operands[0].reg), "!=", "0");
            break;

            /* case MIPS_INS_BNEZL:
                dump_cond_branch_likely(i, r(insn.operands[0].reg), "!=", "0");
                break; */

        case MIPS_INS_C:
            if (insn.mnemonic == "c.lt.s") {
                printf("cf = %s < %s;\n", fr(insn.operands[0].reg), fr(insn.operands[1].reg));
            } else if (insn.mnemonic == "c.le.s") {
                printf("cf = %s <= %s;\n", fr(insn.operands[0].reg), fr(insn.operands[1].reg));
            } else if (insn.mnemonic == "c.eq.s") {
                printf("cf = %s == %s;\n", fr(insn.operands[0].reg), fr(insn.operands[1].reg));
            } else if (insn.mnemonic == "c.lt.d") {
                printf("cf = double_from_FloatReg(%s) < double_from_FloatReg(%s);\n", dr(insn.operands[0].reg),
                       dr(insn.operands[1].reg));
            } else if (insn.mnemonic == "c.le.d") {
                printf("cf = double_from_FloatReg(%s) <= double_from_FloatReg(%s);\n", dr(insn.operands[0].reg),
                       dr(insn.operands[1].reg));
            } else if (insn.mnemonic == "c.eq.d") {
                printf("cf = double_from_FloatReg(%s) == double_from_FloatReg(%s);\n", dr(insn.operands[0].reg),
                       dr(insn.operands[1].reg));
            }
            break;

        case MIPS_INS_CVT:
            if (insn.mnemonic == "cvt.s.w") {
                printf("%s = (int)%s;\n", fr(insn.operands[0].reg), wr(insn.operands[1].reg));
            } else if (insn.mnemonic == "cvt.d.w") {
                printf("%s = FloatReg_from_double((int)%s);\n", dr(insn.operands[0].reg), wr(insn.operands[1].reg));
            } else if (insn.mnemonic == "cvt.d.s") {
                printf("%s = FloatReg_from_double(%s);\n", dr(insn.operands[0].reg), fr(insn.operands[1].reg));
            } else if (insn.mnemonic == "cvt.s.d") {
                printf("%s = double_from_FloatReg(%s);\n", fr(insn.operands[0].reg), dr(insn.operands[1].reg));
            } else if (insn.mnemonic == "cvt.w.d") {
                printf("%s = cvt_w_d(double_from_FloatReg(%s));\n", wr(insn.operands[0].reg), dr(insn.operands[1].reg));
            } else if (insn.mnemonic == "cvt.w.s") {
                printf("%s = cvt_w_s(%s);\n", wr(insn.operands[0].reg), fr(insn.operands[1].reg));
            } else {
                goto unimplemented;
            }
            break;

        case MIPS_INS_CFC1:
            assert(insn.operands[1].reg == MIPS_REG_31);
            printf("%s = fcsr;\n", r(insn.operands[0].reg));
            break;

        case MIPS_INS_CTC1:
            assert(insn.operands[1].reg == MIPS_REG_31);
            printf("fcsr = %s;\n", r(insn.operands[0].reg));
            break;

        case MIPS_INS_DIV:
            if (insn.mnemonic == "div.s") {
                assert(insn.op_count == 3);
                printf("%s = %s / %s;\n", fr(insn.operands[0].reg), fr(insn.operands[1].reg), fr(insn.operands[2].reg));
            } else if (insn.mnemonic == "div.d") {
                assert(insn.op_count == 3);
                printf("%s = FloatReg_from_double(double_from_FloatReg(%s) / double_from_FloatReg(%s));\n",
                       dr(insn.operands[0].reg), dr(insn.operands[1].reg), dr(insn.operands[2].reg));
            } else {
                assert(insn.op_count == 2);
                printf("lo = (int)%s / (int)%s; ", r(insn.operands[0].reg), r(insn.operands[1].reg));
                printf("hi = (int)%s %% (int)%s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg));
            }
            break;

        case MIPS_INS_DIVU:
            assert(insn.op_count == 2);
            printf("lo = %s / %s; ", r(insn.operands[0].reg), r(insn.operands[1].reg));
            printf("hi = %s %% %s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg));
            break;

        case MIPS_INS_MOV:
            if (insn.mnemonic == "mov.s") {
                printf("%s = %s;\n", fr(insn.operands[0].reg), fr(insn.operands[1].reg));
            } else if (insn.mnemonic == "mov.d") {
                printf("%s = %s;\n", dr(insn.operands[0].reg), dr(insn.operands[1].reg));
            } else {
                goto unimplemented;
            }
            break;

        case MIPS_INS_MUL:
            if (insn.mnemonic == "mul.s") {
                printf("%s = %s * %s;\n", fr(insn.operands[0].reg), fr(insn.operands[1].reg), fr(insn.operands[2].reg));
            } else if (insn.mnemonic == "mul.d") {
                printf("%s = FloatReg_from_double(double_from_FloatReg(%s) * double_from_FloatReg(%s));\n",
                       dr(insn.operands[0].reg), dr(insn.operands[1].reg), dr(insn.operands[2].reg));
            } else {
                goto unimplemented;
            }
            break;

        case MIPS_INS_NEG:
            if (insn.mnemonic == "neg.s") {
                printf("%s = -%s;\n", fr(insn.operands[0].reg), fr(insn.operands[1].reg));
            } else if (insn.mnemonic == "neg.d") {
                printf("%s = FloatReg_from_double(-double_from_FloatReg(%s));\n", dr(insn.operands[0].reg),
                       dr(insn.operands[1].reg));
            } else {
                printf("%s = -%s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg));
            }
            break;

        case MIPS_INS_SUB:
            if (insn.mnemonic == "sub.s") {
                printf("%s = %s - %s;\n", fr(insn.operands[0].reg), fr(insn.operands[1].reg), fr(insn.operands[2].reg));
            } else if (insn.mnemonic == "sub.d") {
                printf("%s = FloatReg_from_double(double_from_FloatReg(%s) - double_from_FloatReg(%s));\n",
                       dr(insn.operands[0].reg), dr(insn.operands[1].reg), dr(insn.operands[2].reg));
            } else {
                goto unimplemented;
            }
            break;

        case MIPS_INS_J:
            dump_instr(i + 1);
            printf("goto L%x;\n", (uint32_t)insn.operands[0].imm);
            break;

        case MIPS_INS_JAL: {
            string name;
            bool is_extern_function = false;
            size_t extern_function_id;
            auto it = symbol_names.find(insn.operands[0].imm);

            if (it != symbol_names.end()) {
                name = it->second;

                for (size_t i = 0; i < sizeof(extern_functions) / sizeof(extern_functions[0]); i++) {
                    if (name == extern_functions[i].name) {
                        is_extern_function = true;
                        extern_function_id = i;
                        break;
                    }
                }
            }

            dump_instr(i + 1);

            if (is_extern_function) {
                auto& fn = extern_functions[extern_function_id];

                if (fn.flags & FLAG_VARARG) {
                    for (int j = 0; j < 4; j++) {
                        printf("MEM_U32(sp + %d) = %s;\n", j * 4, r(MIPS_REG_A0 + j));
                    }
                }

                char ret_type = fn.params[0];

                if (ret_type != 'v') {
                    switch (ret_type) {
                        case 'i':
                        case 'u':
                        case 'p':
                            printf("%s = ", r(MIPS_REG_V0));
                            break;

                        case 'f':
                            printf("%s = ", fr(MIPS_REG_F0));
                            break;

                        case 'd':
                            printf("tempf64 = ");
                            break;

                        case 'l':
                        case 'j':
                            printf("temp64 = ");
                            break;
                    }
                }

                printf("wrapper_%s(", name.c_str());

                bool first = true;

                if (!(fn.flags & FLAG_NO_MEM)) {
                    printf("mem");
                    first = false;
                }

                int pos = 0;
                int pos_float = 0;
                bool only_floats_so_far = true;
                bool needs_sp = false;

                for (const char* p = fn.params + 1; *p != '\0'; ++p) {
                    if (!first) {
                        printf(", ");
                    }

                    first = false;

                    switch (*p) {
                        case 't':
                            printf("trampoline, ");
                            needs_sp = true;
                            // fallthrough
                        case 'i':
                        case 'u':
                        case 'p':
                            only_floats_so_far = false;
                            if (pos < 4) {
                                printf("%s", r(MIPS_REG_A0 + pos));
                            } else {
                                printf("MEM_%c32(sp + %d)", *p == 'i' ? 'S' : 'U', pos * 4);
                            }
                            ++pos;
                            break;

                        case 'f':
                            if (only_floats_so_far && pos_float < 4) {
                                printf("%s", fr(MIPS_REG_F12 + pos_float));
                                pos_float += 2;
                            } else if (pos < 4) {
                                printf("BITCAST_U32_TO_F32(%s)", r(MIPS_REG_A0 + pos));
                            } else {
                                printf("BITCAST_U32_TO_F32(MEM_U32(sp + %d))", pos * 4);
                            }
                            ++pos;
                            break;

                        case 'd':
                            if (pos % 1 != 0) {
                                ++pos;
                            }
                            if (only_floats_so_far && pos_float < 4) {
                                printf("double_from_FloatReg(%s)", dr(MIPS_REG_F12 + pos_float));
                                pos_float += 2;
                            } else if (pos < 4) {
                                printf("BITCAST_U64_TO_F64(((uint64_t)%s << 32) | (uint64_t)%s)", r(MIPS_REG_A0 + pos),
                                       r(MIPS_REG_A0 + pos + 1));
                            } else {
                                printf("BITCAST_U64_TO_F64(((uint64_t)MEM_U32(sp + %d) << 32) | (uint64_t)MEM_U32(sp + "
                                       "%d))",
                                       pos * 4, (pos + 1) * 4);
                            }
                            pos += 2;
                            break;

                        case 'l':
                        case 'j':
                            if (pos % 1 != 0) {
                                ++pos;
                            }
                            only_floats_so_far = false;
                            if (*p == 'l') {
                                printf("(int64_t)");
                            }
                            if (pos < 4) {
                                printf("(((uint64_t)%s << 32) | (uint64_t)%s)", r(MIPS_REG_A0 + pos),
                                       r(MIPS_REG_A0 + pos + 1));
                            } else {
                                printf("(((uint64_t)MEM_U32(sp + %d) << 32) | (uint64_t)MEM_U32(sp + %d))", pos * 4,
                                       (pos + 1) * 4);
                            }
                            pos += 2;
                            break;
                    }
                }

                if ((fn.flags & FLAG_VARARG) || needs_sp) {
                    printf("%s%s", first ? "" : ", ", r(MIPS_REG_SP));
                }

                printf(");\n");

                if (ret_type == 'l' || ret_type == 'j') {
                    printf("%s = (uint32_t)(temp64 >> 32);\n", r(MIPS_REG_V0));
                    printf("%s = (uint32_t)temp64;\n", r(MIPS_REG_V1));
                } else if (ret_type == 'd') {
                    printf("%s = FloatReg_from_double(tempf64);\n", dr(MIPS_REG_F0));
                }

                if (!name.empty()) {
                    // printf("printf(\"%s %%x\\n\", %s);\n", name.c_str(), r(MIPS_REG_A0));
                }
            } else {
                Function& f = functions.find((uint32_t)insn.operands[0].imm)->second;

                if (f.nret == 1) {
                    printf("v0 = ");
                } else if (f.nret == 2) {
                    printf("temp64 = ");
                }

                if (!name.empty()) {
                    // printf("printf(\"%s %%x\\n\", %s);\n", name.c_str(), r(MIPS_REG_A0));
                    printf("f_%s", name.c_str());
                } else {
                    printf("func_%x", (uint32_t)insn.operands[0].imm);
                }

                printf("(mem, sp");

                if (f.v0_in) {
                    printf(", %s", r(MIPS_REG_V0));
                }

                for (uint32_t i = 0; i < f.nargs; i++) {
                    printf(", %s", r(MIPS_REG_A0 + i));
                }

                printf(");\n");

                if (f.nret == 2) {
                    printf("%s = (uint32_t)(temp64 >> 32);\n", r(MIPS_REG_V0));
                    printf("%s = (uint32_t)temp64;\n", r(MIPS_REG_V1));
                }
            }

            printf("goto L%x;\n", text_vaddr + (i + 2) * 4);
            label_addresses.insert(text_vaddr + (i + 2) * 4);
        } break;

        case MIPS_INS_JALR:
            printf("fp_dest = %s;\n", r(insn.operands[0].reg));
            dump_instr(i + 1);
            printf("temp64 = trampoline(mem, sp, %s, %s, %s, %s, fp_dest);\n", r(MIPS_REG_A0), r(MIPS_REG_A1),
                   r(MIPS_REG_A2), r(MIPS_REG_A3));
            printf("%s = (uint32_t)(temp64 >> 32);\n", r(MIPS_REG_V0));
            printf("%s = (uint32_t)temp64;\n", r(MIPS_REG_V1));
            printf("goto L%x;\n", text_vaddr + (i + 2) * 4);
            label_addresses.insert(text_vaddr + (i + 2) * 4);
            break;

        case MIPS_INS_JR:
            if (insn.jtbl_addr != 0) {
                uint32_t jtbl_pos = insn.jtbl_addr - rodata_vaddr;

                assert(jtbl_pos < rodata_section_len && jtbl_pos + insn.num_cases * 4 <= rodata_section_len);
#if 1
                printf(";static void *const Lswitch%x[] = {\n", insn.jtbl_addr);

                for (uint32_t i = 0; i < insn.num_cases; i++) {
                    uint32_t dest_addr = read_u32_be(rodata_section + jtbl_pos + i * 4) + gp_value;
                    printf("&&L%x,\n", dest_addr);
                    label_addresses.insert(dest_addr);
                }

                printf("};\n");
                printf("dest = Lswitch%x[%s];\n", insn.jtbl_addr, r(insn.index_reg));
                dump_instr(i + 1);
                printf("goto *dest;\n");
#else
                assert(insns[i + 1].id == MIPS_INS_NOP);
                printf("switch (%s) {\n", r(insn.index_reg));

                for (uint32_t i = 0; i < insn.num_cases; i++) {
                    uint32_t dest_addr = read_u32_be(rodata_section + jtbl_pos + i * 4) + gp_value;
                    printf("case %u: goto L%x;\n", i, dest_addr);
                    label_addresses.insert(dest_addr);
                }

                printf("}\n");
#endif
            } else {
                if (insn.operands[0].reg != MIPS_REG_RA) {
                    printf("UNSUPPORTED JR %s %s\n", insn.op_str.c_str(), r(insn.operands[0].reg));
                } else {
                    dump_instr(i + 1);
                    switch (find_function(text_vaddr + i * 4)->second.nret) {
                        case 0:
                            printf("return;\n");
                            break;

                        case 1:
                            printf("return v0;\n");
                            break;

                        case 2:
                            printf("return ((uint64_t)v0 << 32) | v1;\n");
                            break;
                    }
                }
            }
            break;

        case MIPS_INS_LB:
            printf("%s = MEM_S8(%s + %d);\n", r(insn.operands[0].reg), r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LBU:
            printf("%s = MEM_U8(%s + %d);\n", r(insn.operands[0].reg), r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LH:
            printf("%s = MEM_S16(%s + %d);\n", r(insn.operands[0].reg), r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LHU:
            printf("%s = MEM_U16(%s + %d);\n", r(insn.operands[0].reg), r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LUI:
            printf("%s = 0x%x;\n", r(insn.operands[0].reg), ((uint32_t)insn.operands[1].imm) << 16);
            break;

        case MIPS_INS_LW:
            printf("%s = MEM_U32(%s + %d);\n", r(insn.operands[0].reg), r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LWC1:
            printf("%s = MEM_U32(%s + %d);\n", wr(insn.operands[0].reg), r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LDC1:
            assert((insn.operands[0].reg - MIPS_REG_F0) % 2 == 0);
            printf("%s = MEM_U32(%s + %d);\n", wr(insn.operands[0].reg + 1), r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            printf("%s = MEM_U32(%s + %d + 4);\n", wr(insn.operands[0].reg), r(insn.operands[1].mem.base),
                   (int)insn.operands[1].mem.disp);
            break;

        case MIPS_INS_LWL: {
            const char* reg = r(insn.operands[0].reg);

            printf("%s = %s + %d; ", reg, r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp);
            printf("%s = (MEM_U8(%s) << 24) | (MEM_U8(%s + 1) << 16) | (MEM_U8(%s + 2) << 8) | MEM_U8(%s + 3);\n", reg,
                   reg, reg, reg, reg);
        } break;

        case MIPS_INS_LWR:
            printf("//lwr %s\n", insn.op_str.c_str());
            break;

        case MIPS_INS_LI:
            if (insn.is_global_got_memop && text_vaddr <= insn.operands[1].imm &&
                insn.operands[1].imm < text_vaddr + text_section_len) {
                printf("%s = 0x%x; // function pointer\n", r(insn.operands[0].reg), (uint32_t)insn.operands[1].imm);
                label_addresses.insert((uint32_t)insn.operands[1].imm);
            } else {
                printf("%s = 0x%x;\n", r(insn.operands[0].reg), (uint32_t)insn.operands[1].imm);
            }
            break;

        case MIPS_INS_MFC1:
            printf("%s = %s;\n", r(insn.operands[0].reg), wr(insn.operands[1].reg));
            break;

        case MIPS_INS_MFHI:
            printf("%s = hi;\n", r(insn.operands[0].reg));
            break;

        case MIPS_INS_MFLO:
            printf("%s = lo;\n", r(insn.operands[0].reg));
            break;

        case MIPS_INS_MOVE:
            printf("%s = %s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg));
            break;

        case MIPS_INS_MTC1:
            printf("%s = %s;\n", wr(insn.operands[1].reg), r(insn.operands[0].reg));
            break;

        case MIPS_INS_MULT:
            printf("lo = %s * %s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg));
            printf("hi = (uint32_t)((int64_t)(int)%s * (int64_t)(int)%s >> 32);\n", r(insn.operands[0].reg),
                   r(insn.operands[1].reg));
            break;

        case MIPS_INS_MULTU:
            printf("lo = %s * %s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg));
            printf("hi = (uint32_t)((uint64_t)%s * (uint64_t)%s >> 32);\n", r(insn.operands[0].reg),
                   r(insn.operands[1].reg));
            break;

        case MIPS_INS_SQRT:
            printf("%s = sqrtf(%s);\n", fr(insn.operands[0].reg), fr(insn.operands[1].reg));
            break;

            // case MIPS_INS_FSQRT:
            //     printf("%s = sqrtf(%s);\n", wr(insn.operands[0].reg), wr(insn.operands[1].reg));
            //     break;

        case MIPS_INS_NEGU:
            printf("%s = -%s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg));
            break;

        case MIPS_INS_NOR:
            printf("%s = ~(%s | %s);\n", r(insn.operands[0].reg), r(insn.operands[1].reg), r(insn.operands[2].reg));
            break;

        case MIPS_INS_NOT:
            printf("%s = ~%s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg));
            break;

        case MIPS_INS_OR:
            printf("%s = %s | %s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg), r(insn.operands[2].reg));
            break;

        case MIPS_INS_ORI:
            printf("%s = %s | 0x%x;\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_SB:
            printf("MEM_U8(%s + %d) = (uint8_t)%s;\n", r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp,
                   r(insn.operands[0].reg));
            break;

        case MIPS_INS_SH:
            printf("MEM_U16(%s + %d) = (uint16_t)%s;\n", r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp,
                   r(insn.operands[0].reg));
            break;

        case MIPS_INS_SLL:
            printf("%s = %s << %d;\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_SLLV:
            printf("%s = %s << (%s & 0x1f);\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   r(insn.operands[2].reg));
            break;

        case MIPS_INS_SLT:
            printf("%s = (int)%s < (int)%s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   r(insn.operands[2].reg));
            break;

        case MIPS_INS_SLTI:
            printf("%s = (int)%s < (int)0x%x;\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_SLTIU:
            printf("%s = %s < 0x%x;\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_SLTU:
            printf("%s = %s < %s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg), r(insn.operands[2].reg));
            break;

        case MIPS_INS_SRA:
            printf("%s = (int)%s >> %d;\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_SRAV:
            printf("%s = (int)%s >> (%s & 0x1f);\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   r(insn.operands[2].reg));
            break;

        case MIPS_INS_SRL:
            printf("%s = %s >> %d;\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_SRLV:
            printf("%s = %s >> (%s & 0x1f);\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   r(insn.operands[2].reg));
            break;

        case MIPS_INS_SUBU:
            printf("%s = %s - %s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg), r(insn.operands[2].reg));
            break;

        case MIPS_INS_SW:
            printf("MEM_U32(%s + %d) = %s;\n", r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp,
                   r(insn.operands[0].reg));
            break;

        case MIPS_INS_SWC1:
            printf("MEM_U32(%s + %d) = %s;\n", r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp,
                   wr(insn.operands[0].reg));
            break;

        case MIPS_INS_SDC1:
            assert((insn.operands[0].reg - MIPS_REG_F0) % 2 == 0);
            printf("MEM_U32(%s + %d) = %s;\n", r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp,
                   wr(insn.operands[0].reg + 1));
            printf("MEM_U32(%s + %d + 4) = %s;\n", r(insn.operands[1].mem.base), (int)insn.operands[1].mem.disp,
                   wr(insn.operands[0].reg));
            break;

        case MIPS_INS_SWL:
            for (int i = 0; i < 4; i++) {
                printf("MEM_U8(%s + %d + %d) = (uint8_t)(%s >> %d);\n", r(insn.operands[1].mem.base),
                       (int)insn.operands[1].mem.disp, i, r(insn.operands[0].reg), (3 - i) * 8);
            }
            break;

        case MIPS_INS_SWR:
            printf("//swr %s\n", insn.op_str.c_str());
            break;

        case MIPS_INS_TRUNC:
            if (insn.mnemonic == "trunc.w.s") {
                printf("%s = (int)%s;\n", wr(insn.operands[0].reg), fr(insn.operands[1].reg));
            } else if (insn.mnemonic == "trunc.w.d") {
                printf("%s = (int)double_from_FloatReg(%s);\n", wr(insn.operands[0].reg), dr(insn.operands[1].reg));
            } else {
                goto unimplemented;
            }
            break;

        case MIPS_INS_XOR:
            printf("%s = %s ^ %s;\n", r(insn.operands[0].reg), r(insn.operands[1].reg), r(insn.operands[2].reg));
            break;

        case MIPS_INS_XORI:
            printf("%s = %s ^ 0x%x;\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (uint32_t)insn.operands[2].imm);
            break;

        case MIPS_INS_TNE:
            printf("assert(%s == %s && \"tne %d\");\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (int)insn.operands[2].imm);
            break;

        case MIPS_INS_TEQ:
            printf("assert(%s != %s && \"teq %d\");\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (int)insn.operands[2].imm);
            break;

        case MIPS_INS_TGE:
            printf("assert((int)%s < (int)%s && \"tge %d\");\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (int)insn.operands[2].imm);
            break;

        case MIPS_INS_TGEU:
            printf("assert(%s < %s && \"tgeu %d\");\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (int)insn.operands[2].imm);
            break;

        case MIPS_INS_TLT:
            printf("assert((int)%s >= (int)%s && \"tlt %d\");\n", r(insn.operands[0].reg), r(insn.operands[1].reg),
                   (int)insn.operands[2].imm);
            break;

        case MIPS_INS_NOP:
            printf("//nop;\n");
            break;

        default:
        unimplemented:
            printf("UNIMPLEMENTED %s %s\n", insn.mnemonic.c_str(), insn.op_str.c_str());
            break;
    }
}

static void inspect_data_function_pointers(vector<pair<uint32_t, uint32_t>>& ret, const uint8_t* section,
                                           uint32_t section_vaddr, uint32_t len) {
    for (uint32_t i = 0; i < len; i += 4) {
        uint32_t addr = read_u32_be(section + i);

        if (addr == 0x430b00 || addr == 0x433b00) {
            // in as1, not function pointers (normal integers)
            continue;
        }

        if (addr == 0x4a0000) {
            // in copt
            continue;
        }

        if (section_vaddr + i >= procedure_table_start &&
            section_vaddr + i < procedure_table_start + procedure_table_len) {
            // some linking table with a "all" functions, in as1 5.3
            continue;
        }

        if (addr >= text_vaddr && addr < text_vaddr + text_section_len && addr % 4 == 0) {
#if INSPECT_FUNCTION_POINTERS
            fprintf(stderr, "assuming function pointer 0x%x at 0x%x\n", addr, section_vaddr + i);
#endif
            ret.push_back(make_pair(section_vaddr + i, addr));
            label_addresses.insert(addr);
            functions[addr].referenced_by_function_pointer = true;
        }
    }
}

static void dump_function_signature(Function& f, uint32_t vaddr) {
    printf("static ");
    switch (f.nret) {
        case 0:
            printf("void ");
            break;

        case 1:
            printf("uint32_t ");
            break;

        case 2:
            printf("uint64_t ");
            break;
    }

    auto name_it = symbol_names.find(vaddr);

    if (name_it != symbol_names.end()) {
        printf("f_%s", name_it->second.c_str());
    } else {
        printf("func_%x", vaddr);
    }

    printf("(uint8_t *mem, uint32_t sp");

    if (f.v0_in) {
        printf(", uint32_t %s", r(MIPS_REG_V0));
    }

    for (uint32_t i = 0; i < f.nargs; i++) {
        printf(", uint32_t %s", r(MIPS_REG_A0 + i));
    }

    printf(")");
}

static void dump_c(void) {
    map<string, uint32_t> symbol_names_inv;

    for (auto& it : symbol_names) {
        symbol_names_inv[it.second] = it.first;
    }

    uint32_t min_addr = UINT32_MAX;
    uint32_t max_addr = 0;

    if (data_section_len > 0) {
        min_addr = std::min(min_addr, data_vaddr);
        max_addr = std::max(max_addr, data_vaddr + data_section_len);
    }
    if (rodata_section_len > 0) {
        min_addr = std::min(min_addr, rodata_vaddr);
        max_addr = std::max(max_addr, rodata_vaddr + rodata_section_len);
    }
    if (bss_section_len) {
        min_addr = std::min(min_addr, bss_vaddr);
        max_addr = std::max(max_addr, bss_vaddr + bss_section_len);
    }

    // get pagesize at runtime
#if defined(_WIN32) && !defined(__CYGWIN__)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uint32_t page_size = si.dwPageSize;
#else
    uint32_t page_size = sysconf(_SC_PAGESIZE);
#endif /* _WIN32 && !__CYGWIN__ */
    min_addr = min_addr & ~(page_size - 1);
    max_addr = (max_addr + (page_size - 1)) & ~(page_size - 1);

    uint32_t stack_bottom = min_addr;
    min_addr -= 1 * 1024 * 1024; // 1 MB stack
    stack_bottom -= 16;          // for main's stack frame

    printf("#include \"header.h\"\n");

    if (conservative) {
        printf("static uint32_t s0, s1, s2, s3, s4, s5, s6, s7, fp;\n");
    }

    printf("static const uint32_t rodata[] = {\n");

    for (size_t i = 0; i < rodata_section_len; i += 4) {
        printf("0x%x,%s", read_u32_be(rodata_section + i), i % 32 == 28 ? "\n" : "");
    }

    printf("};\n");
    printf("static const uint32_t data[] = {\n");

    for (size_t i = 0; i < data_section_len; i += 4) {
        printf("0x%x,%s", read_u32_be(data_section + i), i % 32 == 28 ? "\n" : "");
    }

    printf("};\n");

    /* if (!data_function_pointers.empty()) {
        printf("static const struct { uint32_t orig_addr; void *recompiled_addr; } data_function_pointers[] = {\n");
        for (auto item : data_function_pointers) {
            printf("{0x%x, &&L%x},\n", item.first, item.second);
        }
        printf("};\n");
    } */

    if (TRACE) {
        printf("static unsigned long long int cnt = 0;\n");
    }

    for (auto& f_it : functions) {
        if (insns[addr_to_i(f_it.first)].f_livein != 0) {
            // Function is used
            dump_function_signature(f_it.second, f_it.first);
            printf(";\n");
        }
    }

    if (!data_function_pointers.empty() || !li_function_pointers.empty()) {
        printf("uint64_t trampoline(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, "
               "uint32_t fp_dest) {\n");
        printf("switch (fp_dest) {\n");

        for (auto& it : functions) {
            Function& f = it.second;

            if (f.referenced_by_function_pointer) {
                printf("case 0x%x: ", it.first);

                if (f.nret == 1) {
                    printf("return (uint64_t)");
                } else if (f.nret == 2) {
                    printf("return ");
                }

                auto name_it = symbol_names.find(it.first);

                if (name_it != symbol_names.end()) {
                    printf("f_%s", name_it->second.c_str());
                } else {
                    printf("func_%x", it.first);
                }

                printf("(mem, sp");

                for (unsigned int i = 0; i < f.nargs; i++) {
                    printf(", a%d", i);
                }

                printf(")");

                if (f.nret == 1) {
                    printf(" << 32");
                }

                printf(";");

                if (f.nret == 0) {
                    printf(" return 0;");
                }

                printf("\n");
            }
        }

        printf("default: abort();");
        printf("}\n");
        printf("}\n");
    }

    printf("int run(uint8_t *mem, int argc, char *argv[]) {\n");
    printf("mmap_initial_data_range(mem, 0x%x, 0x%x);\n", min_addr, max_addr);

    printf("memcpy(mem + 0x%x, rodata, 0x%x);\n", rodata_vaddr, rodata_section_len);
    printf("memcpy(mem + 0x%x, data, 0x%x);\n", data_vaddr, data_section_len);

    /* if (!data_function_pointers.empty()) {
        if (!LABELS_64_BIT) {
            printf("for (int i = 0; i < %d; i++) MEM_U32(data_function_pointers[i].orig_addr) =
    (uint32_t)(uintptr_t)data_function_pointers[i].recompiled_addr;\n", (int)data_function_pointers.size()); } else {
            printf("for (int i = 0; i < %d; i++) MEM_U32(data_function_pointers[i].orig_addr) =
    (uint32_t)((uintptr_t)data_function_pointers[i].recompiled_addr - (uintptr_t)&&Loffset);\n",
    (int)data_function_pointers.size());
        }
    } */

    printf("MEM_S32(0x%x) = argc;\n", symbol_names_inv.at("__Argc"));
    printf("MEM_S32(0x%x) = argc;\n", stack_bottom);
    printf("uint32_t al = argc * 4; for (int i = 0; i < argc; i++) al += strlen(argv[i]) + 1;\n");
    printf("uint32_t arg_addr = wrapper_malloc(mem, al);\n");
    printf("MEM_U32(0x%x) = arg_addr;\n", symbol_names_inv.at("__Argv"));
    printf("MEM_U32(0x%x) = arg_addr;\n", stack_bottom + 4);
    printf("uint32_t arg_strpos = arg_addr + argc * 4;\n");
    printf("for (int i = 0; i < argc; i++) {MEM_U32(arg_addr + i * 4) = arg_strpos; uint32_t p = 0; do { "
           "MEM_S8(arg_strpos) = argv[i][p]; ++arg_strpos; } while (argv[i][p++] != '\\0');}\n");

    printf("setup_libc_data(mem);\n");

    // printf("gp = 0x%x;\n", gp_value); // only to recreate the outcome when ugen reads uninitialized stack memory

    printf("int ret = f_main(mem, 0x%x", stack_bottom);

    Function& main_func = functions[main_addr];

    if (main_func.nargs >= 1) {
        printf(", argc");
    }

    if (main_func.nargs >= 2) {
        printf(", arg_addr");
    }

    printf(");\n");

    if (TRACE) {
        printf("end: fprintf(stderr, \"cnt: %%llu\\n\", cnt);\n");
    }

    printf("return ret;\n");
    printf("}\n");

    for (auto& f_it : functions) {
        Function& f = f_it.second;
        uint32_t start_addr = f_it.first;
        uint32_t end_addr = f.end_addr;

        if (insns[addr_to_i(start_addr)].f_livein == 0) {
            // Non-used function, skip
            continue;
        }

        printf("\n");
        dump_function_signature(f, start_addr);
        printf(" {\n");
        printf("const uint32_t zero = 0;\n");

        if (!conservative) {
            printf("uint32_t at = 0, v1 = 0, t0 = 0, t1 = 0, t2 = 0,\n");
            printf("t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, s0 = 0, s1 = 0, s2 = 0, s3 = 0, s4 = 0, s5 = 0,\n");
            printf("s6 = 0, s7 = 0, t8 = 0, t9 = 0, gp = 0, fp = 0, s8 = 0, ra = 0;\n");
        } else {
            printf("uint32_t at = 0, v1 = 0, t0 = 0, t1 = 0, t2 = 0,\n");
            printf("t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0, t9 = 0, gp = 0x10000, ra = 0x10000;\n");
        }

        printf("uint32_t lo = 0, hi = 0;\n");
        printf("int cf = 0;\n");
        printf("uint64_t temp64;\n");
        printf("double tempf64;\n");
        printf("uint32_t fp_dest;\n");
        printf("void *dest;\n");

        if (!f.v0_in) {
            printf("uint32_t v0 = 0;\n");
        }

        for (uint32_t j = f.nargs; j < 4; j++) {
            printf("uint32_t %s = 0;\n", r(MIPS_REG_A0 + j));
        }

        for (size_t i = addr_to_i(start_addr), end_i = addr_to_i(end_addr); i < end_i; i++) {
            Insn& insn = insns[i];
            uint32_t vaddr = text_vaddr + i * 4;
            if (label_addresses.count(vaddr)) {
                printf("L%x:\n", vaddr);
            }
            dump_instr(i);
        }

        printf("}\n");
    }
    /* for (size_t i = 0; i < insns.size(); i++) {
        Insn& insn = insns[i];
        uint32_t vaddr = text_vaddr + i * 4;
        auto fn_it = functions.find(vaddr);

        if (fn_it != functions.end()) {
            Function& f = fn_it->second;

            printf("}\n\n");

            switch (f.nret) {
                case 0:
                    printf("void ");
                    break;

                case 1:
                    printf("uint32_t ");
                    break;

                case 2:
                    printf("uint64_t ");
                    break;
            }

            auto name_it = symbol_names.find(vaddr);

            if (name_it != symbol_names.end()) {
                printf("%s", name_it->second.c_str());
            } else {
                printf("func_%x", vaddr);
            }

            printf("(uint8_t *mem, uint32_t sp");

            if (f.v0_in) {
                printf(", uint32_t %s", r(MIPS_REG_V0));
            }

            for (uint32_t i = 0; i < f.nargs; i++) {
                printf(", uint32_t %s", r(MIPS_REG_A0 + i));
            }

            printf(") {\n");
            printf("const uint32_t zero = 0;\n");
            printf("uint32_t at = 0, v1 = 0, t0 = 0, t1 = 0, t2 = 0,\n");
            printf("t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, s0 = 0, s1 = 0, s2 = 0, s3 = 0, s4 = 0, s5 = 0,\n");
            printf("s6 = 0, s7 = 0, t8 = 0, t9 = 0, gp = 0, fp = 0, s8 = 0, ra = 0;\n");
            printf("uint32_t lo = 0, hi = 0;\n");
            printf("int cf = 0;\n");

            if (!f.v0_in) {
                printf("uint32_t v0 = 0;\n");
            }

            for (uint32_t j = f.nargs; j < 4; j++) {
                printf("uint32_t %s = 0;\n", r(MIPS_REG_A0 + j));
            }
        }

        if (label_addresses.count(vaddr)) {
            printf("L%x:\n", vaddr);
        }

        dump_instr(i);
    } */
}

static void parse_elf(const uint8_t* data, size_t file_len) {
    Elf32_Ehdr* ehdr;
    Elf32_Shdr *shdr, *str_shdr, *sym_shdr = NULL, *dynsym_shdr, *dynamic_shdr, *reginfo_shdr, *got_shdr,
                                 *sym_strtab = NULL, *sym_dynstr;
    int text_section_index = -1;
    int symtab_section_index = -1;
    int dynsym_section_index = -1;
    int reginfo_section_index = -1;
    int dynamic_section_index = -1;
    int got_section_index = -1;
    int rodata_section_index = -1;
    int data_section_index = -1;
    int bss_section_index = -1;
    uint32_t text_offset = 0;
    uint32_t vaddr_adj = 0;

    if (file_len < 4 || data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        fprintf(stderr, "Not an ELF file.\n");
        exit(EXIT_FAILURE);
    }

    ehdr = (Elf32_Ehdr*)data;
    if (ehdr->e_ident[EI_DATA] != 2 || u16be(ehdr->e_machine) != 8) {
        fprintf(stderr, "Not big-endian MIPS.\n");
        exit(EXIT_FAILURE);
    }

    if (u16be(ehdr->e_shstrndx) == 0) {
        // (We could look at program headers instead in this case.)
        fprintf(stderr, "Missing section headers; stripped binaries are not yet supported.\n");
        exit(EXIT_FAILURE);
    }

#define SECTION(index) (Elf32_Shdr*)(data + u32be(ehdr->e_shoff) + (index)*u16be(ehdr->e_shentsize))
#define STR(strtab, offset) (const char*)(data + u32be(strtab->sh_offset) + offset)

    str_shdr = SECTION(u16be(ehdr->e_shstrndx));
    for (int i = 0; i < u16be(ehdr->e_shnum); i++) {
        shdr = SECTION(i);

        const char* name = STR(str_shdr, u32be(shdr->sh_name));

        if (strcmp(name, ".text") == 0) {
            text_offset = u32be(shdr->sh_offset);
            text_vaddr = u32be(shdr->sh_addr);
            vaddr_adj = text_vaddr - u32be(shdr->sh_addr);
            text_section_len = u32be(shdr->sh_size);
            text_section = data + text_offset;
            text_section_index = i;
        }

        if (u32be(shdr->sh_type) == SHT_SYMTAB) {
            symtab_section_index = i;
        }

        if (u32be(shdr->sh_type) == SHT_DYNSYM) {
            dynsym_section_index = i;
        }

        if (u32be(shdr->sh_type) == SHT_MIPS_REGINFO) {
            reginfo_section_index = i;
        }

        if (u32be(shdr->sh_type) == SHT_DYNAMIC) {
            dynamic_section_index = i;
        }

        if (strcmp(name, ".got") == 0) {
            got_section_index = i;
        }

        if (strcmp(name, ".rodata") == 0) {
            rodata_section_index = i;
        }

        if (strcmp(name, ".data") == 0) {
            data_section_index = i;
        }

        if (strcmp(name, ".bss") == 0) {
            bss_section_index = i;
        }
    }

    if (text_section_index == -1) {
        fprintf(stderr, "Missing .text section.\n");
        exit(EXIT_FAILURE);
    }

    if (symtab_section_index == -1 && dynsym_section_index == -1) {
        fprintf(stderr, "Missing .symtab or .dynsym section.\n");
        exit(EXIT_FAILURE);
    }

    if (dynsym_section_index != -1) {
        if (reginfo_section_index == -1) {
            fprintf(stderr, "Missing .reginfo section.\n");
            exit(EXIT_FAILURE);
        }

        if (dynamic_section_index == -1) {
            fprintf(stderr, "Missing .dynamic section.\n");
            exit(EXIT_FAILURE);
        }

        if (got_section_index == -1) {
            fprintf(stderr, "Missing .got section.\n");
            exit(EXIT_FAILURE);
        }
    }

    if (rodata_section_index != -1) {
        shdr = SECTION(rodata_section_index);
        uint32_t size = u32be(shdr->sh_size);
        rodata_section = data + u32be(shdr->sh_offset);
        rodata_section_len = size;
        rodata_vaddr = u32be(shdr->sh_addr);
    }

    if (data_section_index != -1) {
        shdr = SECTION(data_section_index);
        uint32_t size = u32be(shdr->sh_size);
        data_section = data + u32be(shdr->sh_offset);
        data_section_len = size;
        data_vaddr = u32be(shdr->sh_addr);
    }

    if (bss_section_index != -1) {
        shdr = SECTION(bss_section_index);
        uint32_t size = u32be(shdr->sh_size);
        bss_section_len = size;
        bss_vaddr = u32be(shdr->sh_addr);
    }

    // add symbols
    if (symtab_section_index != -1) {
        sym_shdr = SECTION(symtab_section_index);
        sym_strtab = SECTION(u32be(sym_shdr->sh_link));
        assert(0 && ".symtab not supported - use a program with .dynsym instead");

        assert(u32be(sym_shdr->sh_entsize) == sizeof(Elf32_Sym));
        for (uint32_t i = 0; i < u32be(sym_shdr->sh_size); i += sizeof(Elf32_Sym)) {
            Elf32_Sym* sym = (Elf32_Sym*)(data + u32be(sym_shdr->sh_offset) + i);
            const char* name = STR(sym_strtab, u32be(sym->st_name));
            uint32_t addr = u32be(sym->st_value);

            if (u16be(sym->st_shndx) != text_section_index || name[0] == '.') {
                continue;
            }

            addr += vaddr_adj;
            // disasm_label_add(state, name, addr, u32be(sym->st_size), true);
        }
    }

    if (dynsym_section_index != -1) {
        dynsym_shdr = SECTION(dynsym_section_index);
        sym_dynstr = SECTION(u32be(dynsym_shdr->sh_link));
        reginfo_shdr = SECTION(reginfo_section_index);
        dynamic_shdr = SECTION(dynamic_section_index);
        got_shdr = SECTION(got_section_index);

        Elf32_RegInfo* reg_info = (Elf32_RegInfo*)(data + u32be(reginfo_shdr->sh_offset));
        uint32_t gp_base = u32be(reg_info->ri_gp_value); // gp should have this value through the program run
        uint32_t got_start = 0;
        uint32_t local_got_no = 0;
        uint32_t first_got_sym = 0;
        uint32_t dynsym_no = 0; // section size can't be used due to alignment 16 padding

        assert(u32be(dynamic_shdr->sh_entsize) == sizeof(Elf32_Dyn));
        for (uint32_t i = 0; i < u32be(dynamic_shdr->sh_size); i += sizeof(Elf32_Dyn)) {
            Elf32_Dyn* dyn = (Elf32_Dyn*)(data + u32be(dynamic_shdr->sh_offset) + i);

            if (u32be(dyn->d_tag) == DT_PLTGOT) {
                got_start = u32be(dyn->d_un.d_ptr);
            }

            if (u32be(dyn->d_tag) == DT_MIPS_LOCAL_GOTNO) {
                local_got_no = u32be(dyn->d_un.d_val);
            }

            if (u32be(dyn->d_tag) == DT_MIPS_GOTSYM) {
                first_got_sym = u32be(dyn->d_un.d_val);
            }

            if (u32be(dyn->d_tag) == DT_MIPS_SYMTABNO) {
                dynsym_no = u32be(dyn->d_un.d_val);
            }
        }

        assert(got_start != 0);

        // value to add to asm gp offset, for example 32752, if -32752(gp) refers to the first entry in got.
        uint32_t gp_adj = gp_base - got_start;

        assert(gp_adj < 0x10000);

        assert(u32be(dynsym_shdr->sh_entsize) == sizeof(Elf32_Sym));

        uint32_t global_got_no = dynsym_no - first_got_sym;
        // global_got_entry *global_entries = (global_got_entry *)calloc(global_got_no, sizeof(global_got_entry));

        got_globals.resize(global_got_no);

        uint32_t common_start = ~0U;
        vector<string> common_order;

        for (uint32_t i = 0; i < dynsym_no; i++) {
            Elf32_Sym* sym = (Elf32_Sym*)(data + u32be(dynsym_shdr->sh_offset) + i * sizeof(Elf32_Sym));
            const char* name = STR(sym_dynstr, u32be(sym->st_name));
            uint32_t addr = u32be(sym->st_value);

            addr += vaddr_adj;

            uint8_t type = ELF32_ST_TYPE(sym->st_info);

            if (!strcmp(name, "_procedure_table")) {
                procedure_table_start = addr;
            } else if (!strcmp(name, "_procedure_table_size")) {
                procedure_table_len = 40 * u32be(sym->st_value);
            }

            if ((u16be(sym->st_shndx) == SHN_MIPS_TEXT && type == STT_FUNC) ||
                (type == STT_OBJECT &&
                 (u16be(sym->st_shndx) == SHN_MIPS_ACOMMON || u16be(sym->st_shndx) == SHN_MIPS_DATA))) {
                // disasm_label_add(state, name, addr, u32be(sym->st_size), true);
                if (type == STT_OBJECT) {}

                if (u16be(sym->st_shndx) == SHN_MIPS_ACOMMON) {
                    if (addr < common_start) {
                        common_start = addr;
                    }

                    common_order.push_back(name);
                }

                if (type == STT_FUNC) {
                    add_function(addr);

                    if (strcmp(name, "main") == 0) {
                        main_addr = addr;
                    }

                    if (strcmp(name, "_mcount") == 0) {
                        mcount_addr = addr;
                    }

                    symbol_names[addr] = name;
                }
            }

            if (i >= first_got_sym) {
                uint32_t got_value = u32be(*(uint32_t*)(data + u32be(got_shdr->sh_offset) +
                                                        (local_got_no + (i - first_got_sym)) * sizeof(uint32_t)));

                if (u16be(sym->st_shndx) == SHN_MIPS_TEXT && type == STT_FUNC) {
                    // got_globals[i - first_got_sym] = got_value;
                    // label_addresses.insert(got_value);
                    got_globals[i - first_got_sym] = addr; // to include the 3 instr gp header thing
                    label_addresses.insert(addr);
                } else if (type == STT_OBJECT &&
                           (u16be(sym->st_shndx) == SHN_UNDEF || u16be(sym->st_shndx) == SHN_COMMON)) {
                    // symbol defined externally (for example in libc)
                    got_globals[i - first_got_sym] = got_value;
                } else {
                    got_globals[i - first_got_sym] = addr;
                }

                symbol_names[got_globals[i - first_got_sym]] = name;
            }
        }

        uint32_t* local_entries = (uint32_t*)calloc(local_got_no, sizeof(uint32_t));
        got_locals.resize(local_got_no);
        for (uint32_t i = 0; i < local_got_no; i++) {
            uint32_t* entry = (uint32_t*)(data + u32be(got_shdr->sh_offset) + i * sizeof(uint32_t));
            got_locals[i] = u32be(*entry);
        }

        gp_value = gp_base;
        gp_value_adj = gp_adj;
        // disasm_got_entries_set(state, gp_base, gp_adj, local_entries, local_got_no, global_entries, global_got_no);

        // out_range.common_start = common_start;
        // out_range.common_order.swap(common_order);
    }

    // add relocations
    for (int i = 0; i < u16be(ehdr->e_shnum); i++) {
        Elf32_Rel* prevHi = NULL;

        shdr = SECTION(i);
        if (u32be(shdr->sh_type) != SHT_REL || u32be(shdr->sh_info) != (uint32_t)text_section_index)
            continue;

        if (sym_shdr == NULL) {
            fprintf(stderr, "Relocations without .symtab section\n");
            exit(EXIT_FAILURE);
        }

        assert(u32be(shdr->sh_link) == (uint32_t)symtab_section_index);
        assert(u32be(shdr->sh_entsize) == sizeof(Elf32_Rel));

        for (uint32_t i = 0; i < u32be(shdr->sh_size); i += sizeof(Elf32_Rel)) {
            Elf32_Rel* rel = (Elf32_Rel*)(data + u32be(shdr->sh_offset) + i);
            uint32_t offset = text_offset + u32be(rel->r_offset);
            uint32_t symIndex = ELF32_R_SYM(u32be(rel->r_info));
            uint32_t rtype = ELF32_R_TYPE(u32be(rel->r_info));
            const char* symName = "0";

            if (symIndex != STN_UNDEF) {
                Elf32_Sym* sym = (Elf32_Sym*)(data + u32be(sym_shdr->sh_offset) + symIndex * sizeof(Elf32_Sym));

                symName = STR(sym_strtab, u32be(sym->st_name));
            }

            if (rtype == R_MIPS_HI16) {
                if (prevHi != NULL) {
                    fprintf(stderr, "Consecutive R_MIPS_HI16.\n");
                    exit(EXIT_FAILURE);
                }

                prevHi = rel;
                continue;
            }

            if (rtype == R_MIPS_LO16) {
                int32_t addend = (int16_t)((data[offset + 2] << 8) + data[offset + 3]);

                if (prevHi != NULL) {
                    uint32_t offset2 = text_offset + u32be(prevHi->r_offset);

                    addend += (uint32_t)((data[offset2 + 2] << 8) + data[offset2 + 3]) << 16;
                    // add_reloc(state, offset2, symName, addend, out_range.vaddr);
                }
                prevHi = NULL;
                // add_reloc(state, offset, symName, addend, out_range.vaddr);
            } else if (rtype == R_MIPS_26) {
                int32_t addend = (u32be(*(uint32_t*)(data + offset)) & ((1 << 26) - 1)) << 2;

                if (addend >= (1 << 27)) {
                    addend -= 1 << 28;
                }
                // add_reloc(state, offset, symName, addend, out_range.vaddr);
            }

            else {
                fprintf(stderr, "Bad relocation type %d.\n", rtype);
                exit(EXIT_FAILURE);
            }
        }

        if (prevHi != NULL) {
            fprintf(stderr, "R_MIPS_HI16 without matching R_MIPS_LO16.\n");
            exit(EXIT_FAILURE);
        }
    }
}
#undef SECTION
#undef STR

size_t read_file(const char* file_name, uint8_t** data) {
    FILE* in;
    uint8_t* in_buf = NULL;
    long file_size;
    long bytes_read;

    in = fopen(file_name, "rb");
    assert(in != nullptr);

    // allocate buffer to read from offset to end of file
    fseek(in, 0, SEEK_END);
    file_size = ftell(in);
    assert(file_size != -1L);

    in_buf = (uint8_t*)malloc(file_size);
    fseek(in, 0, SEEK_SET);

    // read bytes
    bytes_read = fread(in_buf, 1, file_size, in);
    assert(bytes_read == file_size);

    fclose(in);
    *data = in_buf;
    return bytes_read;
}

int main(int argc, char* argv[]) {
    const char* filename = argv[1];

    if (strcmp(filename, "--conservative") == 0) {
        conservative = true;
        filename = argv[2];
    }

    uint8_t* data;
    size_t len = read_file(filename, &data);

    parse_elf(data, len);
    assert(cs_open(CS_ARCH_MIPS, (cs_mode)(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN), &handle) == CS_ERR_OK);

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    disassemble();
    inspect_data_function_pointers(data_function_pointers, rodata_section, rodata_vaddr, rodata_section_len);
    inspect_data_function_pointers(data_function_pointers, data_section, data_vaddr, data_section_len);
    pass1();
    pass2();
    pass3();
    pass4();
    pass5();
    pass6();
    // dump();
    dump_c();
    free(data);
    cs_close(&handle);
}
