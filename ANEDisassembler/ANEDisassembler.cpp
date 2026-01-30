#include <iostream>
#include <cstring>

extern "C" {
#include "ANETD.h"
#include "wmacho.h"
    int _Z24ZinIrRegBitPrintOutDebugILj7EE11ZinIrStatusjRN11ZinHWTraitsIXT_EE6HwTypeEiRNSt3__113basic_ostreamIcNS5_11char_traitsIcEEEE(
            unsigned int, void * /*ZinHWTraits<7u>::HwType &*/, int, std::ostream &);
}
#if !defined(__APPLE__)
extern "C" int _Z24ZinIrRegBitPrintOutDebugILj7EE11ZinIrStatusjRN11ZinHWTraitsIXT_EE6HwTypeEiRNSt3__113basic_ostreamIcNS5_11char_traitsIcEEEE(
        unsigned int, void *, int, std::ostream &) {
    std::cerr << "ZinIrRegBitPrintOutDebug requires ANECompiler (macOS only)\n";
    return 0;
}
#endif
#define DUMP_INST

static uint32_t rd32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint32_t bits32(uint32_t v, uint32_t shift, uint32_t len) {
    if (len >= 32)
        return v >> shift;
    return (v >> shift) & ((1u << len) - 1u);
}

static void dump_hex(const uint8_t *buf, size_t len, size_t base_off) {
    size_t i;
    size_t dump_len = len > 256 ? 256 : len;
    for (i = 0; i < dump_len; i += 16) {
        size_t j;
        printf("    +0x%04zx: ", base_off + i);
        for (j = 0; j < 16 && (i + j) < dump_len; ++j) {
            printf("%02x ", buf[i + j]);
        }
        printf("\n");
    }
    if (dump_len < len) {
        printf("    ... (truncated, total=%zu bytes)\n", len);
    }
}

static void dump_td_header_summary(const uint8_t *td, size_t tdsize) {
    if (tdsize < 28)
        return;
    uint32_t h0 = rd32(td + 0);
    uint32_t h1 = rd32(td + 4);
    uint32_t h2 = rd32(td + 8);
    uint32_t h3 = rd32(td + 12);
    uint32_t h4 = rd32(td + 16);
    uint32_t h5 = rd32(td + 20);
    uint32_t h6 = rd32(td + 24);
    printf("TD header summary: TID=%u NID=%u LNID=%u EON=%u ExeCycles=%u NextSize=%u LogEvents=%u Exceptions=%u DebugLogEvents=%u DebugExceptions=%u NextPointer=0x%08x NextPriority=%u ENE=%u KBase=%u RBase=%u WBase=%u TBase=%u\n",
           bits32(h0, 0, 16), bits32(h0, 16, 8), bits32(h0, 24, 1), bits32(h0, 25, 1),
           bits32(h1, 0, 16), bits32(h1, 16, 8),
           bits32(h2, 0, 16), bits32(h2, 16, 16),
           bits32(h3, 0, 16), bits32(h3, 16, 16),
           h5, bits32(h4, 16, 6), bits32(h6, 16, 8),
           bits32(h6, 0, 3), bits32(h6, 4, 3), bits32(h6, 8, 3), bits32(h6, 12, 3));
    printf("TD header flags: SPL=%u TSR=%u SPC=%u DPC=%u TSE=%u TDE=%u SrcLoc=%u DstLoc=%u TQDis=%u\n",
           bits32(h4, 11, 1), bits32(h4, 12, 1), bits32(h4, 13, 1), bits32(h4, 14, 1),
           bits32(h4, 15, 1), bits32(h4, 24, 1), bits32(h4, 28, 1), bits32(h4, 29, 1),
           bits32(h4, 31, 1));
    if (tdsize >= 32 && (td[19] & 0x1)) {
        uint32_t h7 = rd32(td + 28);
        printf("TD header extra: DTID=%u\n", bits32(h7, 0, 16));
    }
}

static void dump_reg_block_meta(uint32_t idx, size_t regOff, size_t left, const uint32_t *regBlock) {
    if (left < 4) {
        printf("META block %u: off=0x%zx left=%zu (too small for header)\n",
               idx, regOff, left);
        return;
    }
    uint32_t header = regBlock[0];
    uint32_t regCount = header >> 26;
    uint32_t regBaseId = (header >> 2) & 0x00FFFFFF;
    uint32_t valueCount = regCount + 1;
    size_t valuesAvail = (left >= 4) ? ((left - 4) / 4) : 0;
    uint32_t scanCount = (valueCount < valuesAvail) ? valueCount : (uint32_t)valuesAvail;
    uint32_t nonZero = 0;
    for (uint32_t i = 0; i < scanCount; ++i) {
        if (regBlock[i + 1] != 0) {
            nonZero++;
        }
    }
    printf("META block %u: off=0x%zx regBase=0x%06x regCount=%u values=%u nonZero=%u left=%zu",
           idx, regOff, regBaseId, regCount, scanCount, nonZero, left);
    if (valuesAvail < valueCount) {
        printf(" (truncated, need=%u values)", valueCount);
    }
    printf("\n");
}
int parseText(void *ptr, size_t size) {
    uint8_t *text = (uint8_t *)ptr;
    size_t inst_count = size / 0x300;
    if (size % 0x300)
        inst_count++;
    if (inst_count == 0) {
        LOG("no AneInstruction ????\n");
        return -1;
    }
    printf("inst_count == %lu\n", inst_count);
    size_t i;
    for (i = 0; i < inst_count; ++i) {
        uint8_t ZinAneTd_v7[0x350];
        size_t copy_size = 0x300;
        if (i == (inst_count - 1))
            copy_size = size % 0x300;
        memcpy(ZinAneTd_v7, text + 0x300 * i, copy_size);
        memmove(ZinAneTd_v7 + 0x128, ZinAneTd_v7 + 0x7c, 0x300 - 0x7c - 0x5c);
        _Z24ZinIrRegBitPrintOutDebugILj7EE11ZinIrStatusjRN11ZinHWTraitsIXT_EE6HwTypeEiRNSt3__113basic_ostreamIcNS5_11char_traitsIcEEEE(
                i, ZinAneTd_v7, 16, std::cout);
#ifdef DUMP_INST
        char path[64];
        snprintf(path, sizeof(path), "inst%lu.dump", i);
        FILE *fp = fopen(path, "wb");
        if (fp == NULL) {
            printf("open %s failed\n", path);
            continue;
        }
        //if (fwrite(ZinAneTd_v7, sizeof(ZinAneTd_v7), 1, fp) != 1) {
        if (fwrite(text + 0x300 * i, copy_size, 1, fp) != 1) {
            printf("fwrite %s failed\n", path);
        }
        fclose(fp);
#endif
    }
    return 0;
}
/*
 * uint32_t regInfo
 * uint32_t values[regInfo >> 26]
 * uint32_t pad
 *
 */
int parseRegs_v5(uint8_t *regs, size_t size) {
    uint32_t regOff = 0;
    uint32_t i = 0;
    while(regOff < size) {
        uint32_t left = size - regOff;
        if (left < 4) {
            LOG("trailing bytes in reg blob (left=%u), stopping\n", left);
            break;
        }
        uint8_t *ptr = regs + regOff;
        uint32_t regInfo = *(uint32_t *)ptr;
        uint32_t regCnt = regInfo >> 26u;
        uint32_t regAddr = regInfo & 0x3FFFFFFu;
        dump_reg_block_meta(i, regOff, left, (uint32_t *)ptr);
        if (left < (4 + 4 * (regCnt + 1))) {
            size_t k;
            int all_zero = 1;
            for (k = 0; k < left; ++k) {
                if (regs[regOff + k] != 0) {
                    all_zero = 0;
                    break;
                }
            }
            if (!all_zero) {
                LOG("short reg block (left=%u, need=%u), stopping\n",
                    left, (unsigned)(4 + 4 * (regCnt + 1)));
            }
            break;
        }
        printf("idx %u off %lu addr %#010x count %u :\n", i, ptr - regs, regAddr, regCnt);
        uint32_t j;
        int known_group = (i <= 12);
        for (j = 0; j < (regCnt + 1); ++j) {
            uint32_t value = *(uint32_t *)(ptr + 4 + 4 * j);
            if (((regAddr >> 2) + j) >= 0xC0000) {
                LOG("overflow\n");
                return -1;
            }
            printf("    %#010x  %#010x  %u\n", regAddr + 4 * j, value, value);
            if (known_group) {
                switch(i) {
                case 0:
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                    printANETDv5(v5KernelDMASrc, j, 8, value, i);
                    break;
                case 8:
                    printANETDv5(v5Common, j, 8, value, -1);
                    break;
                case 9:
                    printANETDv5(v5TileDMASrc, j, 8, value, -1);
                    break;
                case 10:
                    printANETDv5(v5L2, j, 8, value, -1);
                    break;
                case 11:
                    printANETDv5(v5NE, j, 8, value, -1);
                    break;
                case 12:
                    printANETDv5(v5TileDMADst, j, 8, value, -1);
                    break;
                default:
                    break;
                }
            }
        }
        if (!known_group) {
            size_t block_size = 4 + 4 * (regCnt + 1);
            LOG("unknown aneTDv5 i == %u (hexdump block, addr=%#x count=%u)\n", i, regAddr, regCnt);
            dump_hex(ptr, block_size, regOff);
        }
        regOff = regOff + 4 + regCnt * 4 + 4;
        ++i;
    }
    return 0;
}
int parseText_v5(void *ptr, size_t size) {
#define ANETDv5_SIZE 0x200
#define ANETDv5_SIZE_UNALIG 332
    uint8_t *text = (uint8_t *)ptr;
    size_t inst_count = size / ANETDv5_SIZE;
    if (size % ANETDv5_SIZE)
        inst_count++;
    if (inst_count == 0) {
        LOG("no AneInstruction ????\n");
        return -1;
    }
    printf("inst_count == %lu\n", inst_count);
    size_t i;
    for (i = 0; i < inst_count; ++i) {
        printf("-------------- Insttruction %lu ----------------\n", i);
        size_t tdsize = ANETDv5_SIZE_UNALIG;
        if ((size % ANETDv5_SIZE) && (i == (inst_count - 1)))
            tdsize = size % ANETDv5_SIZE;
        if (tdsize < 29) {
            LOG("bad inst_size\n");
            return -1;
        }
        uint8_t *td = text + ANETDv5_SIZE * i;
        printf("aneTDHeader:\n");
        size_t j;
        for (j = 0; j < 7; ++j) {
            uint32_t intValue = *(uint32_t *)(td + 4 * j);
            printf("intIdx %2lu intValue %8u %#10x :\n", j, intValue, intValue);
            printANETDv5(v5TDHeader, j, 4, *(uint32_t *)(td + 4 * j), -1);
        }
        uint32_t regOff = 28;
        if (td[19] & 0x1) {
            regOff++;
            printANETDv5(v5TDHeader, 7, 4, *(uint32_t *)(td + 4 * j), -1);
        }
        dump_td_header_summary(td, tdsize);
        printf("reg start off %u\n", regOff);
        uint8_t *regs = td + regOff;//skip td head
        if (parseRegs_v5(regs, tdsize - regOff) != 0) {
            LOG("parseRegs_v5 failed\n");
            return -1;
        }
#ifdef DUMP_INST
        char path[64];
        snprintf(path, sizeof(path), "inst%lu.dump", i);
        FILE *fp = fopen(path, "wb");
        if (fp == NULL) {
            printf("open %s failed\n", path);
            continue;
        }
        if (fwrite(text + ANETDv5_SIZE * i, tdsize, 1, fp) != 1) {
            printf("fwrite %s failed\n", path);
        }
        fclose(fp);
#endif
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 2) {
        printf("usage:%s <.hwx file>\n", argv[0]);
        //printf("    now support InstructionSet:v7 only\n");
        return -1;
    }
    int ret = -1;
    struct wmacho w;
    if (wmacho_open(&w, argv[1]) != 0) {
        LOG("wmacho_open failed\n");
        return -1;
    }
    wmacho_dump_load_commands(&w);
    wmacho_dump_sections(&w);
    wmacho_dump_strings(&w);
    void *text;
    size_t text_size;
    if (wmacho_get_sect_by_name(&w, "__text", &text, &text_size) != 0) {
        LOG("wmacho_get_sect_by_name failed\n");
        goto bail;
    }
    printf("__text size is %lu\n", text_size);
    if (parseText_v5(text, text_size) != 0) {
        LOG("parseText failed\n");
        goto bail_text;
    }
    ret = 0;
bail_text:
    free(text);
bail:
    wmacho_close(&w);
    return ret;
}
