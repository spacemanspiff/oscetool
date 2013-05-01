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
 
#ifndef __SCE_BACKEND_H_
#define __SCE_BACKEND_H_

#include "types.h"
#include "list.h"
#include "self.h"

#ifdef __cplusplus
extern "C" {
#endif

extern char *inputfile_path;
extern char *outputfile_path;
extern char *template_path;
extern char *meta_info_value;
extern char *keyset_value;
extern char *filetype_value;
extern char *selftype_value;
extern char *compress_value;
extern char *np_add_sig_value;

extern char *key_revision_value;
extern char *auth_id_value;
extern char *vendor_id_value;
extern char *app_version_value;
extern char *fw_version_value;
extern char *add_section_headers_value;
extern char *skip_sections_value;
extern char *self_control_flags_value;
extern char *self_capability_flags_value;
extern char *sys_process_sdk_version_value;

extern char *np_license_type_value;
extern char *np_app_type_value;
extern char *np_content_id_value;
extern char *np_realfilename_value;

extern int verbose;
extern int raw_output;
extern uint8_t *klicensee;

typedef struct {
	uint32_t license_type;
	uint64_t app_type;
	uint8_t content_id[0x30];
	char *real_filename;
} npdrm_encrypt_info_t;

typedef struct {
	uint64_t self_type;
  	uint64_t key_revision;
  	uint64_t auth_id;
        uint32_t vendor_id;
  	uint64_t app_version;
	uint64_t fw_version;
  	int add_section_headers;
  	int skip_sections;
	uint8_t *control_flags;
  	uint8_t *capability_flags;
  	npdrm_encrypt_info_t *npdrm_info;
} encrypt_options_t;

int backend_cmd_print();
void backend_cmd_encrypt();
void backend_cmd_decrypt();

void flag_header_adjust_endianness(flag_header_t *flag);

int build_self(sce_info_t *sce_info, encrypt_options_t *opts);

#ifdef __cplusplus
}
#endif

#endif /* !_SCE__BACKEND_H_ */
