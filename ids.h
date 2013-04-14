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
 
#ifndef __IDS_H_
#define __IDS_H_

#ifdef __cplusplus
extern "C" {
#endif

#define SELF_TYPE_LV0   1
#define SELF_TYPE_LV1   2
#define SELF_TYPE_LV2   3
#define SELF_TYPE_APP   4
#define SELF_TYPE_ISO   5
#define SELF_TYPE_LDR   6
#define SELF_TYPE_UNK7  7
#define SELF_TYPE_NPDRM 8

#define SCE_TYPE_SELF   1
#define SCE_TYPE_RVK    2
#define SCE_TYPE_PKG    3
#define SCE_TYPE_SPP    4
#define SCE_TYPE_OTHER  5

#define AUTH_ID_FLAG_NOTEQUAL      0
#define AUTH_ID_FLAG_EQUAL         1
#define AUTH_ID_FLAG_LESS          2
#define AUTH_ID_FLAG_LESS_EQUAL    3
#define AUTH_ID_FLAG_GREATER       4
#define AUTH_ID_FLAG_GREATER_EQUAL 5

#define NPDRM_LICENSETYPE_NETWORK 1
#define NPDRM_LICENSETYPE_LOCAL   2
#define NPDRM_LICENSETYPE_FREE    3

extern struct id2name_tbl elf_types[];
extern struct id2name_tbl application_types[];
extern struct id2name_tbl sce_types[];
extern struct id2name_tbl vendor_ids[];
extern struct id2name_tbl auth_ids[];
extern struct id2name_tbl auth_id_flags[];
extern struct id2name_tbl self_types[];
extern struct id2name_tbl controlflags_types[];
extern struct id2name_tbl capability_types[];
extern struct id2name_tbl machine_types[];
extern struct id2name_tbl self_short_name_types[];
extern struct id2name_tbl self_long_name_types[];
extern struct id2name_tbl program_header_types[];
extern struct id2name_tbl section_header_types[];

#ifdef __cplusplus
}
#endif

#endif
