#include "wmacho.h"
#include <ctype.h>

static const char *lc_cmd_name(uint32_t cmd) {
    switch (cmd) {
    case LC_SEGMENT_64: return "LC_SEGMENT_64";
    case LC_UUID: return "LC_UUID";
    case LC_BUILD_VERSION: return "LC_BUILD_VERSION";
    case LC_SOURCE_VERSION: return "LC_SOURCE_VERSION";
    case LC_VERSION_MIN_MACOSX: return "LC_VERSION_MIN_MACOSX";
    case LC_VERSION_MIN_IPHONEOS: return "LC_VERSION_MIN_IPHONEOS";
    case LC_VERSION_MIN_TVOS: return "LC_VERSION_MIN_TVOS";
    case LC_VERSION_MIN_WATCHOS: return "LC_VERSION_MIN_WATCHOS";
    case LC_LOAD_DYLIB: return "LC_LOAD_DYLIB";
    case LC_LOAD_WEAK_DYLIB: return "LC_LOAD_WEAK_DYLIB";
    case LC_REEXPORT_DYLIB: return "LC_REEXPORT_DYLIB";
    case LC_LAZY_LOAD_DYLIB: return "LC_LAZY_LOAD_DYLIB";
    case LC_LOAD_UPWARD_DYLIB: return "LC_LOAD_UPWARD_DYLIB";
    case LC_ID_DYLIB: return "LC_ID_DYLIB";
    case LC_LOAD_DYLINKER: return "LC_LOAD_DYLINKER";
    case LC_ID_DYLINKER: return "LC_ID_DYLINKER";
    case LC_DYLD_ENVIRONMENT: return "LC_DYLD_ENVIRONMENT";
    case LC_RPATH: return "LC_RPATH";
    case LC_NOTE: return "LC_NOTE";
    case LC_SYMTAB: return "LC_SYMTAB";
    case LC_DYSYMTAB: return "LC_DYSYMTAB";
    case LC_FUNCTION_STARTS: return "LC_FUNCTION_STARTS";
    case LC_DATA_IN_CODE: return "LC_DATA_IN_CODE";
    case LC_CODE_SIGNATURE: return "LC_CODE_SIGNATURE";
    default: return "LC_UNKNOWN";
    }
}

static void print_version_u32(uint32_t v) {
    uint32_t major = (v >> 16) & 0xffffu;
    uint32_t minor = (v >> 8) & 0xffu;
    uint32_t patch = v & 0xffu;
    printf("%u.%u.%u", major, minor, patch);
}

static void print_source_version_u64(uint64_t v) {
    uint32_t a = (uint32_t)((v >> 40) & 0x3ffu);
    uint32_t b = (uint32_t)((v >> 30) & 0x3ffu);
    uint32_t c = (uint32_t)((v >> 20) & 0x3ffu);
    uint32_t d = (uint32_t)((v >> 10) & 0x3ffu);
    uint32_t e = (uint32_t)(v & 0x3ffu);
    printf("%u.%u.%u.%u.%u", a, b, c, d, e);
}

static const char *lc_str_safe(struct load_command *cmd, uint32_t cmdsize, uint32_t off) {
    if (off >= cmdsize)
        return NULL;
    const char *s = (const char *)((uint8_t *)cmd + off);
    uint32_t max = cmdsize - off;
    uint32_t i;
    for (i = 0; i < max; ++i) {
        if (s[i] == '\0')
            return s;
    }
    return NULL;
}
int wmacho_open(struct wmacho *w, const char *path) {
    memset(w, 0, sizeof(*w));
    w->fp = fopen(path, "rb");
    if (w->fp == NULL) {
        printf("open %s failed\n", path);
        return -1;
    }
    w->mh = (struct mach_header_64 *)file_read(w->fp, 0, sizeof(*w->mh));
    if (w->mh == NULL) {
        LOG("file_read failed\n");
        goto bail;
    }
    size_t sizeofcmds = w->mh->sizeofcmds;
    free(w->mh);
    w->mh = (struct mach_header_64 *)
        file_read(w->fp, 0, sizeof(*w->mh) + sizeofcmds);
    if (w->mh == NULL) {
        LOG("file_read failed\n");
        goto bail;
    }
    if (w->mh->sizeofcmds != sizeofcmds) {
        LOG("under attack\n");
        free(w->mh);
        goto bail;
    }
    //valid check
    size_t pos = 0,i;
    for (i = 0; i < w->mh->ncmds; ++i) {
        if (pos + sizeof(struct load_command) > sizeofcmds) {
            LOG("bad head\n");
            goto bail_mh;
        }
        struct load_command *cmd = (struct load_command *)
            (((uint8_t *)w->mh) + sizeof(*w->mh) + pos);
        if (cmd->cmdsize < sizeof(struct load_command)) {
            LOG("bad head\n");
            goto bail_mh;
        }
        if ((pos + cmd->cmdsize) > sizeofcmds) {
            LOG("bad head\n");
            goto bail_mh;
        }
        pos += cmd->cmdsize;
    }
    w->cmds = (struct load_command **)
        calloc(sizeof(struct load_command *), w->mh->ncmds);
    if (w->cmds == NULL) {
        LOG("oom\n");
        goto bail_mh;
    }
    pos = 0;
    for (i = 0; i < w->mh->ncmds; ++i) {
        struct load_command *cmd = (struct load_command *)
            (((uint8_t *)w->mh) + sizeof(*w->mh) + pos);
        w->cmds[i] = cmd;
        pos += cmd->cmdsize;
    }
    return 0;
bail_mh:
    free(w->mh);
bail:
    fclose(w->fp);
    return -1;
}
int wmacho_get_sect_by_name(struct wmacho *w, const char *name, void **pptr, size_t *psize) {
    size_t i;
    for (i = 0; i < w->mh->ncmds; ++i) {
        struct load_command *cmd = w->cmds[i];
        if (cmd->cmd != LC_SEGMENT_64)
            continue;
        if (cmd->cmdsize < sizeof(struct segment_command_64)) {
            LOG("bad seg\n");
            return -1;
        }
        struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
        struct section_64 *secs = (struct section_64 *)(((uint8_t *)seg) + sizeof(*seg));
        if (cmd->cmdsize < (sizeof(*seg) + seg->nsects * sizeof(*secs))) {
            LOG("bad seg\n");
            return -1;
        }
        size_t j;
        for (j = 0; j < seg->nsects; ++j) {
            struct section_64 *sec = &secs[j];
            if (strncmp(sec->sectname, name, 16) == 0) {
                void *ptr = file_read(w->fp, sec->offset, sec->size);
                if (ptr == NULL) {
                    LOG("file_read failed\n");
                    return -1;
                }
                *pptr = ptr;
                *psize = sec->size;
                return 0;
            }
        }
    }
    return -1;
}
int wmacho_close(struct wmacho *w) {
    free(w->mh);
    free(w->cmds);
    fclose(w->fp);
    return 0;
}

void wmacho_dump_load_commands(struct wmacho *w) {
    size_t i;
    printf("---- Load Commands ----\n");
    for (i = 0; i < w->mh->ncmds; ++i) {
        struct load_command *cmd = w->cmds[i];
        printf("[%zu] cmd=0x%x (%s) cmdsize=%u\n",
               i, cmd->cmd, lc_cmd_name(cmd->cmd), cmd->cmdsize);
        switch (cmd->cmd) {
        case LC_SEGMENT_64: {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            printf("    segname=%.*s vmaddr=0x%llx vmsize=0x%llx fileoff=0x%llx filesize=0x%llx nsects=%u flags=0x%x\n",
                   16, seg->segname,
                   (unsigned long long)seg->vmaddr,
                   (unsigned long long)seg->vmsize,
                   (unsigned long long)seg->fileoff,
                   (unsigned long long)seg->filesize,
                   seg->nsects, seg->flags);
            break;
        }
        case LC_UUID: {
            struct uuid_command *u = (struct uuid_command *)cmd;
            printf("    uuid=%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
                   u->uuid[0], u->uuid[1], u->uuid[2], u->uuid[3],
                   u->uuid[4], u->uuid[5], u->uuid[6], u->uuid[7],
                   u->uuid[8], u->uuid[9], u->uuid[10], u->uuid[11],
                   u->uuid[12], u->uuid[13], u->uuid[14], u->uuid[15]);
            break;
        }
        case LC_BUILD_VERSION: {
            struct build_version_command *b = (struct build_version_command *)cmd;
            printf("    platform=%u minos=", b->platform);
            print_version_u32(b->minos);
            printf(" sdk=");
            print_version_u32(b->sdk);
            printf(" ntools=%u\n", b->ntools);
            break;
        }
        case LC_SOURCE_VERSION: {
            struct source_version_command *s = (struct source_version_command *)cmd;
            printf("    source_version=");
            print_source_version_u64(s->version);
            printf("\n");
            break;
        }
        case LC_VERSION_MIN_MACOSX:
        case LC_VERSION_MIN_IPHONEOS:
        case LC_VERSION_MIN_TVOS:
        case LC_VERSION_MIN_WATCHOS: {
            struct version_min_command *v = (struct version_min_command *)cmd;
            printf("    minos=");
            print_version_u32(v->version);
            printf(" sdk=");
            print_version_u32(v->sdk);
            printf("\n");
            break;
        }
        case LC_LOAD_DYLIB:
        case LC_LOAD_WEAK_DYLIB:
        case LC_REEXPORT_DYLIB:
        case LC_LAZY_LOAD_DYLIB:
        case LC_LOAD_UPWARD_DYLIB:
        case LC_ID_DYLIB: {
            struct dylib_command *d = (struct dylib_command *)cmd;
            const char *name = lc_str_safe(cmd, cmd->cmdsize, d->dylib.name.offset);
            printf("    name=%s current=", name ? name : "(bad)");
            print_version_u32(d->dylib.current_version);
            printf(" compat=");
            print_version_u32(d->dylib.compatibility_version);
            printf(" timestamp=%u\n", d->dylib.timestamp);
            break;
        }
        case LC_LOAD_DYLINKER:
        case LC_ID_DYLINKER:
        case LC_DYLD_ENVIRONMENT: {
            struct dylinker_command *d = (struct dylinker_command *)cmd;
            const char *name = lc_str_safe(cmd, cmd->cmdsize, d->name.offset);
            printf("    name=%s\n", name ? name : "(bad)");
            break;
        }
        case LC_RPATH: {
            struct rpath_command *r = (struct rpath_command *)cmd;
            const char *path = lc_str_safe(cmd, cmd->cmdsize, r->path.offset);
            printf("    path=%s\n", path ? path : "(bad)");
            break;
        }
        case LC_NOTE: {
            struct note_command *n = (struct note_command *)cmd;
            printf("    owner=%.*s offset=0x%llx size=0x%llx\n",
                   16, n->data_owner,
                   (unsigned long long)n->offset,
                   (unsigned long long)n->size);
            break;
        }
        default:
            break;
        }
    }
}

void wmacho_dump_sections(struct wmacho *w) {
    size_t i;
    printf("---- Sections ----\n");
    for (i = 0; i < w->mh->ncmds; ++i) {
        struct load_command *cmd = w->cmds[i];
        if (cmd->cmd != LC_SEGMENT_64)
            continue;
        struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
        if (cmd->cmdsize < sizeof(*seg))
            continue;
        size_t maxsects = 0;
        if (cmd->cmdsize > sizeof(*seg)) {
            maxsects = (cmd->cmdsize - sizeof(*seg)) / sizeof(struct section_64);
        }
        size_t nsects = seg->nsects;
        if (nsects > maxsects)
            nsects = maxsects;
        struct section_64 *secs = (struct section_64 *)(((uint8_t *)seg) + sizeof(*seg));
        size_t j;
        for (j = 0; j < nsects; ++j) {
            struct section_64 *sec = &secs[j];
            printf("    %.*s.%.*s addr=0x%llx size=0x%llx offset=0x%x\n",
                   16, sec->segname, 16, sec->sectname,
                   (unsigned long long)sec->addr,
                   (unsigned long long)sec->size,
                   sec->offset);
        }
    }
}

void wmacho_dump_strings(struct wmacho *w) {
    size_t fsize = 0;
    if (file_size(w->fp, &fsize) != 0)
        return;
    uint8_t *buf = file_read(w->fp, 0, fsize);
    if (buf == NULL)
        return;
    const char *keywords[] = {
        "version", "Version", "VERSION", "Xcode", "clang",
        "LLVM", "compiler", "Compiler", "ANE", "Build", "build", "sdk", "SDK"
    };
    size_t i = 0;
    size_t printed = 0;
    printf("---- Strings (filtered) ----\n");
    while (i < fsize && printed < 120) {
        while (i < fsize && !isprint((unsigned char)buf[i]))
            i++;
        size_t start = i;
        while (i < fsize && isprint((unsigned char)buf[i]))
            i++;
        size_t len = i - start;
        if (len >= 4 && len < 256) {
            int keep = 0;
            size_t k;
            for (k = 0; k < sizeof(keywords) / sizeof(keywords[0]); ++k) {
                if (memmem(buf + start, len, keywords[k], strlen(keywords[k])) != NULL) {
                    keep = 1;
                    break;
                }
            }
            if (keep) {
                printf("    0x%zx: %.*s\n", start, (int)len, (char *)(buf + start));
                printed++;
            }
        }
        i++;
    }
    free(buf);
}
