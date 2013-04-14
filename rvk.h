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
 
#ifndef __RVK_H_
#define __RVK_H_

#include "self.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RVK_LIST_TYPE0_PROGRAM 4
#define RVK_LIST_TYPE0_PACKAGE 3

typedef struct {
	uint32_t type;
	uint32_t flags;
	uint64_t check;
	uint64_t auth_id;
	uint64_t mask;
} revoke_entry_t;

typedef struct {
 uint32_t type;       /* header type
                       * 3 prg rvk
                       * 4 pkg rvk */
 uint32_t unk1;      /* Unknown. */
 union {
  struct prg {
   uint64_t version;  /* Version. */
  } prg;
  struct pkg {
   uint64_t unk0;    /* Unknown. */
  } pkg;
 };
 uint32_t entry_count;     /* Number of entries. */
 uint8_t padding[12]; /* Padding. */
} revoke_list_header_t;

void print_rvk(FILE *out, sce_info_t *sce_info);
int write_rvk(const char *filename, sce_info_t *sce_info);

#ifdef __cplusplus
}
#endif

#endif
