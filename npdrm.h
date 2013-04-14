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

#ifndef __NPDRM_H_
#define __NPDRM_H_

#include "types.h"
#include "backend.h"
#include "self.h"


#ifdef __cplusplus
extern "C" {
#endif

#define TITLEID_LEN 48

int create_npd_controlflag_payload(npdrm_encrypt_info_t *npdrm_opt, npdrm_info_t *payload);
int decrypt_with_klic(sce_info_t *sce_info);
int npdrm_encrypt(sce_info_t *sce_info);
int add_npdrm_footer_sig(const char *filename);

//npdrm_info_t *npdrm_adjust_endianness_control_flag(sce_info_t *sce_info);
//void npd_controlflag_payload_adjust_endiannes(npdrm_info_t *p);

#ifdef __cplusplus
}
#endif

#endif
