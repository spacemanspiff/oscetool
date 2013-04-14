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
 
#include "backend.h"
#include "util.h"
#include "keys.h"
#include "self.h"
#include "rvk.h"
#include "spp.h"
#include "npdrm.h"
#include "ids.h"
#include "patches.h"

// KEYSET_HEX_LEN = 220
#define KEYSET_HEX_LEN (sizeof(keyset_t) * 2) 
// METADATA_HEX_LEN  = 128
#define METADATA_HEX_LEN (sizeof(metadata_t) *2)

void flag_header_adjust_endianness(flag_header_t *header) {
  header->type = ES32(header->type);
  header->size = ES32(header->size);
  header->next = ES64(header->next); 
}

static int set_encrypt_options_from_template(encrypt_options_t *opts) {
  self_header_t *template = (self_header_t *) _read_buffer(template_path, NULL);

  if (!template) {
    printf("[*] Error: Could not load template %s\n", template_path);
    return 0;
  }
  
  sce_info_t *sce_info = process_sce_file(template);
  if (!sce_info) {
    printf("[*] Error: Could not process template %s\n", template_path);
    free(template);
    return 0;
  }
  
  if (!decrypt_header(sce_info, NULL, NULL)) {
    printf("[*] Warning: Could not decrypt template header.\n");
    free(sce_info);
    free(template);
    return 0;
  }
  
  if (verbose)
    printf("[*] Template header decrypted.\n");
	
  opts->key_revision = template->sce_header.key_revision;
  
  opts->auth_id = sce_info->info_header->authid;
  opts->self_type = sce_info->info_header->self_type;
  opts->vendor_id = sce_info->info_header->vendor_id;
  opts->app_version = sce_info->info_header->version;


  opts->add_section_headers = 1;
  if (add_section_headers_value)
    if(!strcmp(add_section_headers_value, "FALSE") )
      opts->add_section_headers = 0;

  opts->skip_sections = 1;
  if ( skip_sections_value ) 
    if ( !strcmp(skip_sections_value, "FALSE") )
      opts->skip_sections = 0;
  
  list_node_t *node = list_head(sce_info->control_flag_list);
  control_flag_t *flag = (control_flag_t *) list_get(node);
  while (flag->header.type != CONTROLFLAG_TYPE_CONTROL) {
    node = list_next(node);
    if (!node) {
      flag = NULL;
      break;
    }
    flag = (control_flag_t *) list_get(node);
  }
  if (flag) {
    uint8_t *custom_control_flags = malloc(0x20);
    if (custom_control_flags)
      memcpy(custom_control_flags, &flag->control_flags, 0x20);
    opts->control_flags = custom_control_flags;
  }
  
  node = list_head(sce_info->control_flag_list);
  flag = (control_flag_t *) list_get(node);
  while (flag->header.type != CONTROLFLAG_TYPE_FILEDIGEST) {
    node = list_next(node);
    if (!node) {
      flag = NULL;
      break;
    }
    flag = (control_flag_t *) list_get(node);
  }
  if (flag) {
    filedigest_adjust_endianness(&flag->file_digest);
    opts->fw_version = flag->file_digest.version;
  }
  
  node = list_head(sce_info->capability_list);
  capability_flag_t *cap = (capability_flag_t *) list_get(node);
  while (cap->header.type != CONTROLFLAG_TYPE_CONTROL) {
    node = list_next(node);
    if (!node) {
      cap = NULL;
      break;
    }
    cap = (capability_flag_t *) list_get(node);
  }
  if (cap) {
    uint8_t *custom_capabilities = malloc(sizeof(capability_flag_t));
    if (custom_capabilities)
      memcpy(custom_capabilities, &cap->payload, sizeof(capability_flag_t));
    opts->capability_flags = custom_capabilities;	
  }
  opts->npdrm_info = NULL;

  return 1;
}

static patch_options_t *set_patch_options() {
  patch_options_t *patch_opts = NULL;

  if (sys_process_sdk_version_value) {
	if (strlen(sys_process_sdk_version_value) != 8) {
    		printf("[*] Warning: SDK Version should be 4 bytes long.\n");
		return NULL;
	}
	patch_opts = malloc(sizeof(patch_opts));
  	patch_opts->sdk_version = x_to_u64((char *)sys_process_sdk_version_value);
  }
  return patch_opts;

}

int set_encrypt_options(encrypt_options_t *opts) {
  if (!key_revision_value) {
    printf("[*] Error: Please specify a key revision.\n");
    return 0;
  }

  if (!valid_hex(key_revision_value)) {
    printf("[*] Error (Key Revision): Please provide a valid hexadecimal number.\n");
    return 0;
  }
  opts->key_revision = x_to_u64(key_revision_value);
  if (!auth_id_value) {
    printf("[*] Error: Please specify an auth ID.\n");
    return 0;
  }

  opts->auth_id = x_to_u64((char *)auth_id_value);
  if (!vendor_id_value) {
    printf("[*] Error: Please specify a vendor ID.\n");
    return 0;
  }

  opts->vendor_id = x_to_u64((char *)vendor_id_value);
  if (!selftype_value) {
    printf("[*] Error: Please specify a SELF type.\n");
    return 0;
  }

  uint64_t self_type = name2id(selftype_value, self_short_name_types, 0xFFFFFFFF);
  if (self_type == 0xFFFFFFFF ) {
    printf("[*] Error: Invalid SELF type.\n");
    return 0;
  }
  opts->self_type = self_type;

  if ( !app_version_value) {
    printf("[*] Error: Please specify an application version.\n");
    return 0;
  }
  opts->app_version = x_to_u64(app_version_value);

  opts->fw_version = 0;
  if (fw_version_value)
    opts->fw_version = x_to_u64(fw_version_value);

  opts->add_section_headers = 1;
  if (add_section_headers_value && !strcmp(add_section_headers_value, "FALSE"))
    opts->add_section_headers = 0;
  
  opts->skip_sections = 1;
  if (skip_sections_value) {
    if (!strcmp(skip_sections_value, "FALSE"))
      opts->skip_sections = 0;
  }

  opts->control_flags = NULL;
  if (self_control_flags_value) {
    if (strlen(self_control_flags_value) != 64) {
      printf("[*] Error: Control flags need to be 32 bytes.\n");
      return 0;
    }
    opts->control_flags = x_to_u8_buffer(self_control_flags_value);
  }

  opts->capability_flags = NULL;
  if (self_capability_flags_value) {
    if (strlen(self_capability_flags_value) != 64) {
      printf("[*] Error: Capability flags need to be 32 bytes.\n");
      return 0;
    }
    opts->capability_flags = x_to_u8_buffer(self_capability_flags_value);
  }

  opts->npdrm_info = NULL;

  return 1;
}



int set_npdrm_encrypt_options(encrypt_options_t *opts) {

  npdrm_encrypt_info_t *npdrm_info = (npdrm_encrypt_info_t *) malloc(sizeof(npdrm_encrypt_info_t));
  opts->npdrm_info = npdrm_info;
  if (!np_license_type_value) {
    printf("[*] Error: Please specify a license type.\n");
    return 0;
  }
  if ( strcmp(np_license_type_value, "FREE") ) {
    if ( strcmp(np_license_type_value, "LOCAL") ) {
      printf("[*] Error: Only supporting LOCAL and FREE license for now.\n");
      return 0;
    }
    npdrm_info->license_type = NPDRM_LICENSETYPE_LOCAL;
  } else {
    npdrm_info->license_type = NPDRM_LICENSETYPE_FREE;
  }
  if (!np_app_type_value) {
    printf("[*] Error: Please specify an application type.\n");
    return 0;
  }
  
  uint64_t app_type = name2id(np_app_type_value, application_types, 0xFFFFFFFF);
  if ( app_type == 0xFFFFFFFF ) {
    printf("[*] Error: Invalid application type.\n");
    return 0;
  }
  npdrm_info->app_type = app_type;
  if (!np_content_id_value) {
    printf("[*] Error: Please specify a content ID.\n");
    return 0;
  }
  strncpy((char *) npdrm_info->content_id, np_content_id_value, 0x30);
  //memcpy(npdrm_info->content_id, np_content_id_value, 0x30);
  if (!np_realfilename_value) {
    printf("[*] Error: Please specify a real filename.\n");
    return 0;
  }
  npdrm_info->real_filename = np_realfilename_value;
  
  return 1;
}

int backend_cmd_print() {
  self_header_t *inputfile = (self_header_t *) _read_buffer(inputfile_path, NULL);
  if (!inputfile) {
    printf("[*] Error: Could not load %s\n", inputfile_path);
    return 0;
  }

  sce_info_t *sce_info = process_sce_file(inputfile);
  if (!sce_info) {
    printf("[*] Error: Could not process %s\n", inputfile_path);
    free(inputfile);
    return 0;
  }
	
  metadata_t *metadata_override = NULL;
  if (meta_info_value) {
    if ( strlen(meta_info_value) != 128 ) {
      printf("[*] Error: Metadata info needs to be 64 bytes.\n");
      return 0;
    }
    metadata_override = (metadata_t *) x_to_u8_buffer(meta_info_value);
  }
  
  keyset_raw_t *keyset_override = NULL;
  if (keyset_value) {
    if ( strlen(keyset_value) != 220 ) {
      printf("[*] Error: Keyset has a wrong length.\n");
      return 0;
    }
    keyset_override = (keyset_raw_t *)x_to_u8_buffer(keyset_value);
  }
  
  if (decrypt_header(sce_info, keyset_override, metadata_override)) {
    if (verbose)
      printf("[*] Header decrypted.\n");

    if (decrypt_sections(sce_info)) {
      if ( verbose != 1 )
	printf("[*] Data decrypted.\n");

    } else {
      printf("[*] Warning: Could not decrypt data.\n");
    }
  }else {
    printf("[*] Warning: Could not decrypt header.\n");
  }
  
  print_header_data(stdout, sce_info);
  
  if (sce_info->sce_header->type == SCE_TYPE_SELF) {
    print_self(stdout, sce_info);
  } else if (sce_info->sce_header->type  == SCE_TYPE_RVK && sce_info->metadata_decrypted) {
    print_rvk(stdout, sce_info);
  } else if (sce_info->sce_header->type  == SCE_TYPE_SPP && sce_info->metadata_decrypted) {
    print_spp(stdout, sce_info);
  }
	
  free(keyset_override);
  free(metadata_override);
  
  free(sce_info);
  free(inputfile);
  return 1;
}

void backend_cmd_decrypt() {
  self_header_t *inputfile = (self_header_t *) _read_buffer(inputfile_path, NULL);
  if (!inputfile) {
    printf("[*] Error: Could not load %s\n", inputfile_path);
    return;
  }

  sce_info_t *sce_info = (sce_info_t *) process_sce_file(inputfile);
  if (!sce_info) {
    printf("[*] Error: Could not process %s\n", inputfile_path);
    free(inputfile);
    return;
  }	

  metadata_t *metadata_override = NULL;
  if (meta_info_value) {
    if ( strlen(meta_info_value) != 128 ) {
      printf("[*] Error: Metadata info needs to be 64 bytes.\n");
      return;
    }
    metadata_override = (metadata_t *) x_to_u8_buffer(meta_info_value);
  }
  
  keyset_raw_t *keyset_override = NULL;
  if (keyset_value) {
    if ( strlen(keyset_value) != 220 ) {
      printf("[*] Error: Keyset has a wrong length.\n");
      return;
    }
    keyset_override = (keyset_raw_t *)x_to_u8_buffer(keyset_value);
  }
	
  if (!decrypt_header(sce_info, keyset_override, metadata_override)) {
    printf("[*] Warning: Could not decrypt header.\n");
    free(inputfile);
    free(sce_info);
    return;		
  }

  if (verbose)
    printf("[*] Header decrypted.\n");
		
  if (!decrypt_sections(sce_info)) {
    printf("[*] Warning: Could not decrypt data.\n");
    free(inputfile);
    free(sce_info);
    return;
  }
	
  if (verbose)
    printf("[*] Data decrypted.\n");

  if (sce_info->sce_header->type == SCE_TYPE_SELF) {
    if (write_elf(outputfile_path, sce_info)) {
      printf("[*] ELF written to %s.\n", outputfile_path);
    } else {
      printf("[*] Error: Could not write ELF.\n");
    }
  } else if (sce_info->sce_header->type == SCE_TYPE_RVK) {
    if (write_rvk(outputfile_path, sce_info)) {
      printf("[*] RVK written to %s.\n", outputfile_path);
    } else {
      printf("[*] Error: Could not write RVK.\n");
    }
  } else if (sce_info->sce_header->type == SCE_TYPE_PKG) {
    printf("soon...\n");
  } else if (sce_info->sce_header->type == SCE_TYPE_SPP) {
    if (write_spp(outputfile_path, sce_info)) {
      printf("[*] SPP written to %s.\n", outputfile_path);
    } else {
      printf("[*] Error: Could not write SPP.\n");
    }
  }
  free(inputfile);
  free(sce_info);	
  return;
}

void backend_cmd_encrypt() {
  uint32_t file_size;
  sce_info_t *sce_info = NULL;
  encrypt_options_t opts;
  patch_options_t *patch_opts;

  if (!filetype_value) {
    printf("[*] Error: Please specify a file type.\n");
    return;
  }
  keyset_raw_t *keyset_override = NULL;
  if (keyset_value) {
    if (strlen(keyset_value) != 220) {
      printf("[*] Error: Keyset has a wrong length.\n");
      return;
    }
    keyset_override = (keyset_raw_t *) x_to_u8_buffer(keyset_value);
  }

  uint8_t *inputfile = (uint8_t *) _read_buffer(inputfile_path, &file_size);
  if (!inputfile) {
    printf("[*] Error: Could not read %s\n", inputfile_path);
    return;
  }

  int can_compress = 0;
  if ( strcmp(filetype_value, "SELF") ) {
    if ( !strcmp(filetype_value, "RVK") || 
	 !strcmp(filetype_value, "PKG") || 
	 !strcmp(filetype_value, "SPP") ) {
      printf("soon...\n");
      return;
    }
  } else {
    if ( !selftype_value) {
      if ( !template_path ) {
        printf("[*] Error: Please specify a SELF type.\n");
        return;
      }
    }
    int res = (template_path)?
    		set_encrypt_options_from_template(&opts):
      		set_encrypt_options(&opts);
    if (!res)
      return;

    patch_opts = set_patch_options();

    if (opts.self_type == SELF_TYPE_NPDRM)
      if (!set_npdrm_encrypt_options(&opts))
	return;

    sce_info = create_self_info(inputfile, file_size);

    patch_elf(sce_info->elf_data, patch_opts);

    if (!build_self(sce_info, &opts)) {
      printf("[*] Error: SELF not built.\n");
      return;
    }
    printf("[*] SELF built.\n");

    if (!(opts.self_type == SELF_TYPE_LDR || opts.self_type == SELF_TYPE_ISO))
      can_compress = 1;
  }

  if (compress_value && strcmp(compress_value, "TRUE") == 0) {
    if (can_compress) {
      compress_sections(sce_info);
      printf("[*] Data compressed.\n");
    } else {
      printf("[*] Warning: This type of file will not be compressed.\n");
    }
  }

  self_fill_header(sce_info);
  build_self_header(sce_info);

  if (!encrypt_metadata(sce_info, keyset_override) ) {
    printf("[*] Error: Data not encrypted.\n");
    return;
  }

  self_encrypt_sections(sce_info);
  printf("[*] Data encrypted.\n");
  if (!write_self(outputfile_path, sce_info)) {
    printf("[*] Error: %s not written.\n", outputfile_path);
    return;
  }
  printf("[*] %s written.\n", outputfile_path);
  
  if (opts.self_type == SELF_TYPE_NPDRM) {
    if (np_add_sig_value && !strcmp(np_add_sig_value, "TRUE")) {
      if (add_npdrm_footer_sig(outputfile_path))
	printf("[*] Added NPDRM footer signature.\n");
      else
	printf("[*] Error: Could not add NPDRM footer signature.\n");
    }
  }
}
