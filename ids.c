/*
 *  Copyright (C) 2013, Spaceman Spiff
 *
 *  This file is part of Open SCE Tool.
 *
 *  Open SCE Tool is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Open SCE Tool is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCETool.  If not, see <http://www.gnu.org/licenses/>.
 */
 
#include "util.h" 
#include "ids.h" 

struct id2name_tbl controlflags_types[] = {
  { 1,   "Flags" },
  { 2,   "Digest" },
  { 3,   "NPDRM" },
  { 0LL, NULL }
};

struct id2name_tbl capability_types[] = {
  { 1,   "Capability Flags" },
  { 0LL, NULL }
};
struct id2name_tbl vendor_ids[] = {
  { 0x0FF000000, "hv" },
  { 0x007000001, "system" },
  { 0x001000002, "normal" },
  { 0x005000002, "lv2" }, 
  { 0x002000003, "ps2emu" }, 
  { 0LL,         NULL }
};

struct id2name_tbl auth_ids[] = {
  { 0x1010000001000003ll, "retail game/update" }, 
  { 0x1020000401000001ll, "ps2emu" }, 
  { 0x1050000003000001ll, "lv2_kernel" }, 
  { 0x1070000001000002ll, "onicore_child" }, 
  { 0x1070000002000002ll, "mcore" }, 
  { 0x1070000003000002ll, "mgvideo" }, 
  { 0x1070000004000002ll, "swagner, swreset" }, 
  { 0x1070000017000001ll, "ss_init (lv1)" }, 
  { 0x107000001A000001ll, "ss_sc_init_pu (lv1)" }, 
  { 0x107000001C000001ll, "updater_frontend (lv1)" }, 
  { 0x107000001D000001ll, "sysmgr_ss (lv1)" }, 
  { 0x107000001F000001ll, "sb_iso_spu_module" }, 
  { 0x1070000020000001ll, "sc_iso, sc_iso_factory" }, 
  { 0x1070000021000001ll, "spp_verifier" }, 
  { 0x1070000022000001ll, "spu_pkg_rvk_verifier" }, 
  { 0x1070000023000001ll, "spu_token_processor" }, 
  { 0x1070000024000001ll, "sv_iso_spu_module" }, 
  { 0x1070000025000001ll, "Aim_spu_module" }, 
  { 0x1070000026000001ll, "ss_sc_init_pu (lv1)" }, 
  { 0x1070000028000001ll, "factory_data_mngr_sever (lv1)" }, 
  { 0x1070000029000001ll, "fdm_spu_module" }, 
  { 0x1070000032000001ll, "ss_server1 (lv1)" }, 
  { 0x1070000033000001ll, "ss_server2 (lv1)" }, 
  { 0x1070000034000001ll, "ss_server3 (lv1)" }, 
  { 0x1070000037000001ll, "mc_iso_spu_module" }, 
  { 0x1070000039000001ll, "bdp_bdmv" }, 
  { 0x107000003A000001ll, "bdj" }, 
  { 0x1070000040000001ll, "sys/external modules" }, 
  { 0x1070000041000001ll, "ps1emu" }, 
  { 0x1070000043000001ll, "me_iso_spu_module" }, 
  { 0x1070000046000001ll, "spu_mode_auth" }, 
  { 0x107000004C000001ll, "spu_utoken_pro" }, 
  { 0x1070000052000001ll, "sys/internal + vsh/module modules" }, 
  { 0x1070000055000001ll, "manu_info_spu_module" }, 
  { 0x1070000058000001ll, "me_iso_for_ps2emu" }, 
  { 0x1070000059000001ll, "sv_iso_for_ps2emu" }, 
  { 0x1070000300000001ll, "Lv2diag BD Remarry" }, 
  { 0x10700003FC000001ll, "emer_init" }, 
  { 0x10700003FD000001ll, "ps3swu" }, 
  { 0x10700003FF000001ll, "Lv2diag FW Stuff" }, 
  { 0x1070000409000001ll, "pspemu" }, 
  { 0x107000040A000001ll, "psp_translator" }, 
  { 0x107000040B000001ll, "pspemu modules" }, 
  { 0x107000040C000001ll, "pspemu drm" }, 
  { 0x1070000500000001ll, "cellftp" }, 
  { 0x1070000501000001ll, "hdd_copy" }, 
  { 0x10700005FC000001ll, "sys_audio" }, 
  { 0x10700005FD000001ll, "sys_init_osd" }, 
  { 0x10700005FF000001ll, "vsh" }, 
  { 0x1FF0000001000001ll, "lv0" }, 
  { 0x1FF0000002000001ll, "lv1" }, 
  { 0x1FF0000008000001ll, "lv1ldr" }, 
  { 0x1FF0000009000001ll, "lv2ldr" }, 
  { 0x1FF000000A000001ll, "isoldr" }, 
  { 0x1FF000000C000001ll, "appldr" }, 
  { 0LL,                  NULL }
};

struct id2name_tbl auth_id_flags[] = {
  { AUTH_ID_FLAG_NOTEQUAL,      "!=" },
  { AUTH_ID_FLAG_EQUAL,         "==" },
  { AUTH_ID_FLAG_LESS,          "<" },
  { AUTH_ID_FLAG_LESS_EQUAL,    "<=" },	
  { AUTH_ID_FLAG_GREATER,       ">" },
  { AUTH_ID_FLAG_GREATER_EQUAL, ">=" },
  { 0LL,                        NULL }
};

struct id2name_tbl sce_types[] = {
  { SCE_TYPE_SELF,  "SELF" },
  { SCE_TYPE_RVK,   "RVK" },
  { SCE_TYPE_PKG,   "PKG" },
  { SCE_TYPE_SPP,   "SPP" },
  { SCE_TYPE_OTHER, "OTHER" },
  { 0LL,            NULL }
};

struct id2name_tbl self_short_name_types[] = {
  { SELF_TYPE_LV0,   "LV0" },
  { SELF_TYPE_LV1,   "LV1" },
  { SELF_TYPE_LV2,   "LV2" },
  { SELF_TYPE_APP,   "APP" },
  { SELF_TYPE_ISO,   "ISO" },
  { SELF_TYPE_LDR,   "LDR" },
  { SELF_TYPE_NPDRM, "NPDRM" },
  { 0LL,             NULL }
};

struct id2name_tbl self_long_name_types[] = {
  { SELF_TYPE_LV0,   "lv0" },
  { SELF_TYPE_LV1,   "lv1" },
  { SELF_TYPE_LV2,   "lv2" },
  { SELF_TYPE_APP,   "Application" },
  { SELF_TYPE_ISO,   "Isolated SPU Module" },
  { SELF_TYPE_LDR,   "Secure Loader" },
  { SELF_TYPE_UNK7,  "Unknown 7" },
  { SELF_TYPE_NPDRM, "NPDRM Application" },
  { 0LL,             NULL }
};

struct id2name_tbl machine_types[] = {
  { 0x14, "PPC" },
  { 0x15, "PPC64" },
  { 0x17, "SPU" },
  { 0LL,  NULL }
};
struct id2name_tbl elf_types[] = {
  { 0x0002, "EXEC"},
  { 0xFFA4, "SPRX"},
  { 0LL,    NULL }
};
struct id2name_tbl program_header_types[] = {
  { 0x01,       "LOAD" },
  { 0x02,       "DYNAMIC" },
  { 0x03,       "INTERP" },
  { 0x04,       "NOTE" },
  { 0x05,       "SHLIB" },
  { 0x06,       "PHDR" },
  { 0x07,       "TLS" },
  { 0x08,       "NUM" },
  { 0x60000001, "PARAMS" },
  { 0x60000002, "PRX" },
  { 0x70000004, "PRXRELOC" },
  { 0LL,        NULL }
};

struct id2name_tbl section_header_types[] = {
  { 0x00, "NULL" },
  { 0x01, "PROGBITS" },
  { 0x02, "SYMTAB" },
  { 0x03, "STRTAB" },
  { 0x04, "RELA" },
  { 0x05, "HASH" },
  { 0x06, "DYNAMIC" },
  { 0x07, "NOTE" },
  { 0x08, "NOBITS" },	
  { 0x09, "REL" },
  { 0x0A, "SHLIB" },
  { 0x0B, "DYNSYM" },
  { 0x0E, "INIT_ARRAY" },
  { 0x0F, "FINI_ARRAY" },
  { 0x10, "PREINIT_ARRAY" },
  { 0x11, "GROUP" },
  { 0x12, "SYMTAB_SHNDX" },
  { 0LL,  NULL }
};

struct id2name_tbl application_types[] = {
  { 0x00, "SPRX" },
  { 0x01, "EXEC" },
  { 0x20, "USPRX" },
  { 0x21, "UEXEC" },
  { 0LL,  NULL }
};


