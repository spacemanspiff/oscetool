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
 
#include "self.h"

#include "backend.h"
#include "keys.h"
#include "util.h"
#include "npdrm.h" 
#include "ids.h"
#include "mt19937.h"

#include "polarssl/sha1.h"
#include "polarssl/aes.h"

#include <zlib.h>
#include <time.h>
#include "ec.h"

static void section_info_adjust_endianness(section_info_t *si);

static void sce_header_adjust_endianness(sce_hdr_t *h) {
  h->magic = ES32(h->magic);
  h->version = ES32(h->version);
  h->key_revision = ES16(h->key_revision);
  h->type = ES16(h->type);
  h->metadata_offset = ES32(h->metadata_offset);
  h->header_len = ES64(h->header_len);
  h->data_filesize = ES64(h->data_filesize);
};

static void metadata_header_adjust_endianness(metadata_header_t *h) {
  h->signature_input_length = ES64(h->signature_input_length);
  h->unknown0 = ES32(h->unknown0);
  h->section_count = ES32(h->section_count);
  h->key_count = ES32(h->key_count);
  h->signature_info_size = ES32(h->signature_info_size);
  h->unknown1 = ES32(h->unknown1);
  h->unknown2 = ES32(h->unknown2);
}

static void metadata_section_header_adjust_endianness(metadata_section_header_t *h) {
  h->data_offset = ES64(h->data_offset);
  h->data_size = ES64(h->data_size);
  h->type = ES32(h->type); 
  h->program_idx = ES32(h->program_idx);
  h->hashed = ES32(h->hashed);
  h->sha1_idx = ES32(h->sha1_idx);
  h->encrypted = ES32(h->encrypted); 
  h->key_idx = ES32(h->key_idx);
  h->iv_idx = ES32(h->iv_idx);
  h->compressed = ES32(h->compressed); 
}

static void sce_extended_header_adjust_endianness(self_extended_header_t *h) {
  h->header_type = ES64(h->header_type);
  h->appinfo_offset = ES64(h->appinfo_offset);
  h->elf_offset = ES64(h->elf_offset);
  h->phdr_offset = ES64(h->phdr_offset);
  h->shdr_offset = ES64(h->shdr_offset);
  h->section_info_offset= ES64(h->section_info_offset);
  h->sceversion_offset = ES64(h->sceversion_offset);
  h->controlinfo_offset = ES64(h->controlinfo_offset);
  h->controlinfo_size = ES64(h->controlinfo_size);
  h->padding = ES64(h->padding);
}

static void sce_sdkversion_adjust_endianness(sdkversion_t *h) {
  h->type = ES32(h->type);
  h->present = ES32(h->present);
  h->size = ES32(h->size);
  h->unknown3 = ES32(h->unknown3);
}

static void sce_info_header_adjust_endianness(info_header_t *h) {
  h->authid = ES64(h->authid);
  h->vendor_id = ES32(h->vendor_id);
  h->self_type = ES32(h->self_type);
  h->version = ES64(h->version);
  h->padding = ES64(h->padding);
}

static void capability_flag_payload_adjust_endianness(capability_flag_payload_t *p) {
  p->unknown3 = ES64(p->unknown3);
  p->unknown4 = ES64(p->unknown4);
  p->flags = ES64(p->flags);
  p->unknown6 = ES32(p->unknown6);
  p->unknown7 = ES32(p->unknown7);
}

static void print_sce_header(FILE *out, sce_hdr_t *h) {
  fprintf(out, "[*] SCE Header:\n");
  fprintf(out, " Magic           0x%08X [%s]\n", h->magic, (h->magic == SCE_MAGIC)?"OK":"ERROR");
  fprintf(out, " Version         0x%08X\n", h->version);

  if ( h->key_revision == 0x8000u )
    fprintf(out, " Key Revision    [DEBUG]\n");
  else
    fprintf(out, " Key Revision    0x%04X\n", h->key_revision);

  const char *header_type = id2name(h->type, sce_types, NULL);
  if (header_type) {
    printf(" Header Type     [%s]\n", header_type);
  } else {
    printf(" Header Type     0x%04X\n", h->type);
  }

  fprintf(out, " Metadata Offset 0x%08X\n", h->metadata_offset);
  fprintf(out, " Header Length   0x%016" PRIX64 "\n", h->header_len);
  fprintf(out, " Data Length     0x%016" PRIX64 "\n",h->data_filesize);
}

static void print_metadata_key(FILE *out, metadata_t *keys) {
  fprintf(out, "[*] Metadata Info:\n");
  _hexdump(out, " Key", 0, keys->key, sizeof(keys->key), 0);
  _hexdump(out, " IV ", 0, keys->iv, sizeof(keys->iv), 0);
  //_hexdump(out, " Raw ", 0, keys->key, 64, 0);
}

static void print_metadata_header(FILE *out, metadata_header_t *h) {
  fprintf(out, "[*] Metadata Header:\n");
  fprintf(out, " Signature Input Length 0x%016" PRIX64 "\n", h->signature_input_length);
  fprintf(out, " unknown_0              0x%08X\n", h->unknown0);
  fprintf(out, " Section Count          0x%08X\n", h->section_count);
  fprintf(out, " Key Count              0x%08X\n", h->key_count);
  fprintf(out, " Optional Header Size   0x%08X\n", h->signature_info_size);
  fprintf(out, " unknown_1              0x%08X\n", h->unknown1);
  fprintf(out, " unknown_2              0x%08X\n", h->unknown2);
}

static void print_metadata_section_header_entry(FILE *out, 
						metadata_section_header_t *section_header, 
						int index) {
  fprintf(out, " %03d %08" PRIX64 " %08" PRIX64 " %02X   %02X    ",
	  index,
	  section_header->data_offset, 
	  section_header->data_size,
	  section_header->type, 
	  section_header->program_idx);

  if (section_header->hashed == METADATA_SECTION_HASHED_YES)
    fprintf(out, "[YES]  %02X   ", section_header->sha1_idx);
  else
    fprintf(out, "[NO ]  --   ");

  if (section_header->encrypted == METADATA_SECTION_ENCRYPTED_YES)
    fprintf(out, "[YES]     %02X  %02X ", section_header->key_idx, section_header->iv_idx);
  else
    fprintf(out, "[NO ]     --  -- ");

  if (section_header->compressed == METADATA_SECTION_COMPRESSED_YES)
    fprintf(out, "[YES]\n");
  else
    fprintf(out, "[NO ]\n") ;
}

static void print_metadata_section_header(FILE *out, sce_info_t *sce_info) {
  fprintf(out, "[*] Metadata Section Headers:\n");
  fprintf(out, " Idx Offset   Size     Type Index Hashed SHA1 Encrypted Key IV Compressed\n");

  if (sce_info->metadata_header->section_count) {
    uint32_t i = 0;
    metadata_section_header_t *section_header = sce_info->metadata_section_header;
    while (i < sce_info->metadata_header->section_count) {
      print_metadata_section_header_entry(out, section_header, i);
      ++section_header;
      ++i;
    }
  }
}

static void print_sce_file_keys(FILE *out, sce_info_t *sce_info) {
  fprintf(stdout, "[*] SCE File Keys:\n");

  if (sce_info->metadata_header->key_count) {
    uint32_t index = 0;
    uint8_t *key = (uint8_t *) sce_info->metadata_section_header + 
      sce_info->metadata_header->section_count * sizeof(metadata_section_header_t);
    while (index < sce_info->metadata_header->key_count) {
      fprintf(out, " %02X:", index++);
      _hexdump(out, "", 0, key, 16, 0);
      key += 16;			
    }	
  }
}

static sce_info_t *init_sce_info_and_metadata_keys() {
  sce_info_t *sce_info = (sce_info_t *) malloc(sizeof(sce_info_t));
  if (!sce_info)
    return NULL;
  memset(sce_info, 0, sizeof(sce_info_t));  
  sce_info->output = NULL;
 
  sce_hdr_t *sce_header = (sce_hdr_t *) malloc(sizeof(sce_hdr_t)); 
  memset(sce_header, 0, sizeof(sce_hdr_t));
  sce_info->sce_header = sce_header;
  
  // Create metadata AES keys
  sce_info->metadata_decrypted = 1; 
  sce_info->metadata_aes_keys = (metadata_t *) malloc(sizeof(metadata_t));	

  get_rand(sce_info->metadata_aes_keys->key, 16);
  memset(sce_info->metadata_aes_keys->key_pad, 0, 16);	
  get_rand(sce_info->metadata_aes_keys->iv, 16);
  memset(sce_info->metadata_aes_keys->iv_pad, 0, 16);
#if 0
  uint32_t len = 0;
  uint8_t *keys= _read_buffer("keys_meta", &len);
  if (len >= 64) {
	memcpy(sce_info->metadata_aes_keys, keys, 64);
  }
  print_metadata_key(stdout, sce_info->metadata_aes_keys);
#endif

  // Allocate metadata header
  sce_info->metadata_header = (metadata_header_t *) malloc(sizeof(metadata_header_t));
  
  // Allocate signture
  sce_info->signature = (signature_t *) malloc(sizeof(signature_t));

  // No elf data yet
  sce_info->elf_data = NULL;

  return sce_info;
}

sce_info_t *process_sce_file(self_header_t *scefile) {
  sce_info_t *sce_info = (sce_info_t *) malloc(sizeof(sce_info_t));
  if (!sce_info) 
    return NULL;

  memset(sce_info, 0, sizeof(sce_info_t));
  sce_info->output = (uint8_t *) scefile;
  sce_info->sce_header = &scefile->sce_header;
  sce_info->metadata_decrypted = 0;
  sce_header_adjust_endianness(&scefile->sce_header);

  switch (scefile->sce_header.type) {
  case SCE_TYPE_SELF:
    sce_info->extended_header = &scefile->ext_header;
    sce_extended_header_adjust_endianness(sce_info->extended_header);
    
    // Info header
    sce_info->info_header = (void *)scefile + scefile->ext_header.appinfo_offset;
    sce_info_header_adjust_endianness(sce_info->info_header);
    sce_info->section_info = (void *)scefile + scefile->ext_header.section_info_offset;
    
    // SDK Version
    if (scefile->ext_header.sceversion_offset != 0) {
      sce_info->sdkversion = (void *)scefile + scefile->ext_header.sceversion_offset;
      sce_sdkversion_adjust_endianness(sce_info->sdkversion);
    } else {
      sce_info->sdkversion = 0;
    }
    
    // Control Flags
    int left = scefile->ext_header.controlinfo_size;
    if (left) {
      sce_info->control_flag_list = list_alloc();
      control_flag_t *cflag = (control_flag_t *)((void *)scefile + scefile->ext_header.controlinfo_offset);
      while (left) {
	flag_header_adjust_endianness(&cflag->header);
	list_append(sce_info->control_flag_list, cflag);
	left -= cflag->header.size;
	cflag = (control_flag_t *) ((void *) cflag + cflag->header.size);
      }
    } else {
      sce_info->control_flag_list = NULL;
    }
    
  case SCE_TYPE_RVK:
  case SCE_TYPE_PKG:
  case SCE_TYPE_SPP: {
    uint32_t metadata_offset = scefile->sce_header.metadata_offset + METADATA_INFO_UNKNOWN_SIZE; 
    sce_info->metadata_aes_keys = (metadata_t *) ((uint8_t *)scefile + metadata_offset);
    sce_info->metadata_header = (metadata_header_t *) ((uint8_t *) sce_info->metadata_aes_keys + sizeof(metadata_t));
    sce_info->metadata_section_header = (metadata_section_header_t *) ((uint8_t *) sce_info->metadata_header + sizeof(metadata_header_t));
    break;
  }
  default:
    free(sce_info);
    sce_info = NULL;
    break;
  }

  return sce_info;
}

sce_info_t *create_self_info(uint8_t *elf, int size) {
  sce_info_t *sce_info = init_sce_info_and_metadata_keys();

  if (!sce_info)
    return 0;
  
  sce_hdr_t *sce_header = sce_info->sce_header;
  sce_header->magic = SCE_MAGIC; /*0x53434500*/
  sce_header->version = 2;
  sce_header->type = SCE_TYPE_SELF;
	
  sce_info->extended_header = (self_extended_header_t *) malloc(sizeof(self_extended_header_t));
  memset(sce_info->extended_header, 0, sizeof(self_extended_header_t));
  sce_info->extended_header->header_type = SCE_EXT_HEADER_TYPE_SELF;
	
	
  sce_info->info_header = (info_header_t *) malloc(sizeof(info_header_t));
  sce_info->info_header->authid = 0;
  sce_info->info_header->vendor_id = 0;
  sce_info->info_header->self_type = 0;
  sce_info->info_header->version = 0;
  sce_info->info_header->padding = 0;
  
  // New SDK Version Structure
  sce_info->sdkversion = (sdkversion_t *) malloc(sizeof(sdkversion_t));
  
  // New control flag list
  sce_info->control_flag_list = list_alloc();
  
  // New capability flags list
  sce_info->capability_list = list_alloc();

  // Fill ELF data
  sce_info->elf_data = (elf_data_t *) malloc(sizeof(elf_data_t));	
  sce_info->elf_data->header = NULL;
  sce_info->elf_data->header_size = 0;
  sce_info->elf_data->program_header = NULL;
  sce_info->elf_data->program_header_size = 0;
  sce_info->elf_data->section_header = NULL;
  sce_info->elf_data->section_header_size = 0;
  sce_info->elf_data->self_program_header_count = 0;
  sce_info->elf_data->self_section_info_count = 0;
  sce_info->elf_data->image = elf;
  sce_info->elf_data->image_size = size;

  // New Section List
  sce_info->sections_list = list_alloc();
  
  return sce_info;
}

static void append_section_entry_to_list(sce_info_t *sce_info, 
					 uint8_t *ptr, uint32_t size, int compressed) {
  section_entry_t *section_entry = (section_entry_t *) malloc(sizeof(section_entry_t));
  section_entry->ptr = ptr;
  section_entry->size = size;
  section_entry->compressed = compressed;
  list_append(sce_info->sections_list, section_entry);
}

void compress_sections(sce_info_t *sce_info) {
  list_node_t *node = list_head(sce_info->sections_list);
  uint32_t i = 0;
  while (node) {
    section_list_entry_t *section = (section_list_entry_t *) list_get(node);
    if (section->compressed) {
      if (section->size) {
	uLongf compressed_size = compressBound(section->size);
	uint8_t *compressed_buffer = malloc(compressed_size);
	compress(compressed_buffer, &compressed_size, section->ptr, section->size);
	if (compressed_size >= section->size) {
	  free(compressed_buffer);
	  if (verbose)
	    printf("[*] Skipped compression of section %03d (0x%08lX >= 0x%08X)\n", i, compressed_size, section->size);
	} else {
	  section->ptr = compressed_buffer;
	  section->size = compressed_size;
	  if (sce_info->sce_header->type == SCE_TYPE_SELF) {
	    if ( i < sce_info->elf_data->self_section_info_count) {
	      section_info_t *section_info  = &sce_info->section_info[i];
	      section_info->compressed = SECTION_INFO_COMPRESSED_YES;
	      section_info->size = compressed_size;
	    }
	  }
	  sce_info->metadata_section_header[i].compressed = METADATA_SECTION_COMPRESSED_YES;
	}
      } else {
	if (verbose)
	  printf("[*] Skipped compression of section %03d (size is zero)\n", i);
      }
    }
    node = list_next(node);
    ++i;
  }
}

static void complete_headers(sce_info_t *sce_info) {
  list_node_t *node = list_head(sce_info->sections_list);
  
  sce_hdr_t *self_header = sce_info->sce_header;
  uint32_t current_pos = self_header->header_len;
  uint32_t prev_offset = 0;
  uint32_t section_count = 0;

  if (node) {
    metadata_section_header_t *msh = sce_info->metadata_section_header;

    while (node) {
      section_entry_t *section_entry = (section_entry_t *) list_get(node);
      section_entry->offset = current_pos;
      if ( self_header->type == SCE_TYPE_SELF ) {
        if ( section_count < sce_info->elf_data->self_section_info_count) {
          section_info_t *section_info = (section_info_t *)sce_info->section_info;
	  
	  section_info[section_count].offset = current_pos;
        }
      }
      msh->data_offset = current_pos;
      msh->data_size = section_entry->size;
      prev_offset = current_pos;
      uint32_t next_pos = section_entry->size + current_pos;
      self_header->data_filesize = next_pos - self_header->header_len;
      current_pos = ALIGN(next_pos, 16);
      ++section_count;
      ++msh;
      node = list_next(node);
    }
  }
  self_header->metadata_offset = sce_info->metadata_aes_keys_offset - METADATA_INFO_UNKNOWN_SIZE;
  metadata_header_t *metadata_header = sce_info->metadata_header;
  metadata_header->signature_input_length = sce_info->signature_offset;
  node = list_head(sce_info->capability_list);
  capability_flag_t *capf = (capability_flag_t *) list_get(node);
  uint32_t capability_size = 0;
  if (node != NULL) {
    while (node) {
      capf = (capability_flag_t *) list_get(node);
      capability_size += capf->header.size;
      node = list_next(node);
    }
  }
  metadata_header->signature_info_size = capability_size;
  metadata_header->unknown0 = 1;
  metadata_header->unknown1 = 0;
  metadata_header->unknown2 = 0;
 
  if (self_header->type == SCE_TYPE_SELF) {
    self_extended_header_t *ext_header = (self_extended_header_t *) sce_info->extended_header;
    
    ext_header->appinfo_offset = sce_info->info_header_offset;
    ext_header->elf_offset =sce_info->elf_header_offset;
    ext_header->phdr_offset = sce_info->elf_program_header_offset;
    ext_header->section_info_offset = sce_info->section_info_offset;
    ext_header->sceversion_offset = sce_info->sdk_version_offset;
    ext_header->controlinfo_offset = sce_info->control_flags_offset;
	
    list_t *controlList = sce_info->control_flag_list;
    list_node_t *node = list_head(controlList);
    uint32_t size = 0;
    while (node != NULL) {
      control_flag_t *cf = (control_flag_t *) list_get(node);
      size += cf->header.size;
      node = list_next(node);
    }
    ext_header->controlinfo_size = size;
    ext_header->shdr_offset = (sce_info->elf_data->section_header)?prev_offset:0;
  }
}

static void init_metadata_keys(sce_info_t *sce_info) {
  metadata_header_t *metadata_header = (metadata_header_t *)sce_info->metadata_header;
  sce_info->metadata_keys_size = 0;
  metadata_header->key_count = 0;
  uint32_t i = 0;
  while (i < sce_info->metadata_header->section_count) {
    metadata_section_header_t *msh = &sce_info->metadata_section_header[i];

    // Is encrypted? If encrypted we need 8 keys, if not 6
    if (msh->encrypted == METADATA_SECTION_ENCRYPTED_YES) {
      sce_info->metadata_keys_size += 8 * 16;
      sce_info->metadata_header->key_count += 8;
      msh->sha1_idx = sce_info->metadata_header->key_count - 8;
      msh->key_idx  = sce_info->metadata_header->key_count - 2;
      msh->iv_idx   = sce_info->metadata_header->key_count - 1;
    } else {
      sce_info->metadata_keys_size += 6 * 16;
      sce_info->metadata_header->key_count += 6;
      msh->sha1_idx = sce_info->metadata_header->key_count - 6;
      msh->key_idx  = -1;
      msh->iv_idx   = -1;		
    }
    ++i;
  }
  
  sce_info->metadata_keys = (uint8_t *) malloc(sce_info->metadata_keys_size);
  get_rand(sce_info->metadata_keys, sce_info->metadata_keys_size);
#if 0
  uint32_t len;
  uint8_t *keys= _read_buffer("keys", &len);
  if (len >= sce_info->metadata_keys_size) {
	memcpy(sce_info->metadata_keys, keys, 
		sce_info->metadata_keys_size);
  }
  print_metadata_key(stdout, sce_info->metadata_aes_keys);
  return;
#endif
  
  // Set first hmac-key -- SCETool specific?
  char hmac_part4[17];
  time_t now = time(NULL);
  struct tm *tm = localtime(&now);
  sprintf(hmac_part4,"%02d%02d%02d::%02d%02d%04d", 
		tm->tm_hour, 
		tm->tm_min, 
		tm->tm_sec, 
		tm->tm_mday, 
		tm->tm_mon, 
		tm->tm_year + 1900);
  
  section_hash_t *first_key = (section_hash_t *) sce_info->metadata_keys;
  static uint8_t hmac_part1[] = "SURPRIZE :D ";
  static uint8_t hmac_part2[] = "IM IN UR KEYZ !!";
  //{ 0xAEBEB809, 0xA617C083, 0x50B0113B, 0xF9EDCEC4 };
  static uint8_t hmac_part3[] = { 0x09, 0xb8, 0xbe, 0xae, 0x83, 0xc0, 0x17, 0xa6, 
		  	     0x3b, 0x11, 0x0b, 0x05, 0xc4, 0xce, 0xed, 0xf9};
  
  int idx = 0;
  memcpy(first_key->hmac_key,hmac_part1, 12); idx += 16;
  memcpy(first_key->hmac_key + idx,hmac_part2, 16); idx += 16;
  memcpy(first_key->hmac_key + idx,hmac_part3, 16); idx += 16;
  memcpy(first_key->hmac_key + idx,hmac_part4, 16); 

}

void self_fill_header(sce_info_t *sce_info) {
  sce_info->sce_header_offset = 0;
  uint32_t metadata_aes_keys_offset = 32;

  if (sce_info->sce_header->type == SCE_TYPE_SELF) {
    elf_data_t *elf_data = sce_info->elf_data;

    uint32_t elf_prog_header_size = elf_data->program_header_size;	
    sce_info->extended_header_offset = sizeof(sce_hdr_t);	
    sce_info->info_header_offset = sizeof(sce_hdr_t) + sizeof(self_extended_header_t);
    sce_info->elf_header_offset = sce_info->info_header_offset + sizeof(info_header_t);
    uint32_t elf_header_size = elf_data->header_size;
    uint32_t elf_prog_header_count = elf_data->self_program_header_count;

    uint32_t elf_program_header_offset = ALIGN(elf_header_size + 
					  sizeof(sce_hdr_t) + 
					  sizeof(self_extended_header_t) + 
					  sizeof(info_header_t), 16);
    sce_info->elf_program_header_offset = elf_program_header_offset;
	
    uint32_t section_header_offset = ALIGN(elf_program_header_offset + elf_prog_header_size, 16);
    sce_info->section_info_offset = section_header_offset;
    int sdk_version_offset = ALIGN( section_header_offset + 
				    sizeof(section_info_t) * elf_prog_header_count, 16);
    sce_info->sdk_version_offset = sdk_version_offset;
    sce_info->control_flags_offset = ALIGN(sdk_version_offset + sizeof(sdkversion_t), 16);

    uint32_t len = 0;
    list_t *control_flag_list = sce_info->control_flag_list;    
    list_node_t *node = list_head(control_flag_list); 
    while (node) {
      control_flag_t *cf = (control_flag_t *) list_get(node);
      len += cf->header.size;
      node = list_next(node);
    }
    metadata_aes_keys_offset = ALIGN(sce_info->control_flags_offset + len, 16);
  }

  sce_info->metadata_aes_keys_offset = metadata_aes_keys_offset;
  uint32_t metadata_header_offset = ALIGN(sce_info->metadata_aes_keys_offset + sizeof(metadata_t), 16);
  sce_info->metadata_header_offset = metadata_header_offset;

  uint32_t metadata_section_header_offset = ALIGN(metadata_header_offset + sizeof(metadata_header_t), 16);
  sce_info->metadata_section_header_offset = metadata_section_header_offset;

  uint32_t section_count = sce_info->metadata_header->section_count;
  uint32_t metadata_keys_offset = ALIGN(metadata_section_header_offset + 
				   sizeof(metadata_section_header_t) * section_count, 16);
  sce_info->metadata_keys_offset = metadata_keys_offset;
  init_metadata_keys(sce_info);
  
  uint32_t signature_offset = ALIGN(sce_info->metadata_keys_size + metadata_keys_offset, 16);
  
  if (sce_info->sce_header->type == SCE_TYPE_SELF) {
    sce_info->capability_flags_offset = signature_offset;
    uint32_t len = 0;
    list_t *capability_list = sce_info->capability_list;
    list_node_t *node = list_head(capability_list); 
    while (node) {
      capability_flag_t *cap = (capability_flag_t *) list_get(node);
      len += cap->header.size;
      node = list_next(node);
    }
    signature_offset = ALIGN(signature_offset + len, 16);
  }
  sce_info->signature_offset = signature_offset;
  
  uint32_t header_len = ALIGN(signature_offset + sizeof(signature_t), 16);
  sce_info->end_of_header = header_len;  
  sce_info->sce_header->header_len = ALIGN(header_len, 0x80);
  complete_headers(sce_info);
}

void build_self_header(sce_info_t *sce_info) {
  uint32_t sce_header_len = sce_info->sce_header->header_len;

  uint8_t *new_header = (uint8_t *) malloc(sce_header_len);
  memset(new_header, 0, sce_header_len);
  sce_info->output = new_header;

  // Copy SCE Header
  sce_hdr_t *sce_head = (sce_hdr_t *) (new_header + sce_info->sce_header_offset);
  memcpy(sce_head, sce_info->sce_header, sizeof(sce_hdr_t));
  sce_header_adjust_endianness(sce_head);
  
  if ( (sce_info->sce_header->type) == SCE_TYPE_SELF ) {
    // Copy extended header
    self_extended_header_t *ext_header = (self_extended_header_t *)(new_header + 
								    sce_info->extended_header_offset);
    memcpy((uint8_t *) ext_header,
	   (uint8_t *) sce_info->extended_header,
	   sizeof(self_extended_header_t));
    sce_extended_header_adjust_endianness(ext_header);
	
    // Copy info header
    info_header_t *info_header = (info_header_t *) (new_header + sce_info->info_header_offset);
    memcpy((uint8_t *) info_header, 
	   (uint8_t *) sce_info->info_header, sizeof(info_header_t));
    sce_info_header_adjust_endianness(info_header);
	
    // Copy elf header
    elf_data_t *elf_data = sce_info->elf_data;
    memcpy(new_header + sce_info->elf_header_offset, elf_data->header, elf_data->header_size);

    // Copy program header from elf
    memcpy( new_header + sce_info->elf_program_header_offset,
	    elf_data->program_header,
	    elf_data->program_header_size);
	  
    // Copy Section Info
    uint32_t cont = 0;
    if ( elf_data->self_program_header_count ) {
      section_info_t *section_info =  (section_info_t *) (new_header + sce_info->section_info_offset);
      while (cont < elf_data->self_program_header_count) {
        memcpy(&section_info[cont],
	       &sce_info->section_info[cont],
	       sizeof(section_info_t));
        section_info_adjust_endianness(&section_info[cont]);
	++cont;
      }
    }	
	
    // Copy SDK Version Info
    sdkversion_t *sdk_version = (sdkversion_t *) (new_header + sce_info->sdk_version_offset);
    sdk_version->type = sce_info->sdkversion->type;
    sdk_version->present = sce_info->sdkversion->present;
    sdk_version->size = sce_info->sdkversion->size;
    sdk_version->unknown3 = sce_info->sdkversion->unknown3;
    sce_sdkversion_adjust_endianness(sdk_version);
    
    // Copy control flags
    list_node_t *node = list_head(sce_info->control_flag_list);
    uint32_t control_flag_offset = sce_info->control_flags_offset; 
    while (node) {
      control_flag_t *cf = (control_flag_t *) list_get(node);
      control_flag_t *new = (control_flag_t *) (new_header + control_flag_offset);
      new->header.type = cf->header.type;
      new->header.size = cf->header.size;
      new->header.next = cf->header.next;
      flag_header_adjust_endianness(&new->header);
      memcpy((uint8_t *) &new->control_flags, (uint8_t *) &cf->control_flags, cf->header.size - 16);
      control_flag_offset += cf->header.size;
      node = list_next(node);
    }
  }
  
  // Copy metadata aes_keys
  memcpy(new_header + sce_info->metadata_aes_keys_offset,
	(const void *)sce_info->metadata_aes_keys, sizeof(metadata_t));
	
  // Copy metadata_header
  metadata_header_t *metadata_header = (metadata_header_t *)(new_header + sce_info->metadata_header_offset);
  memcpy((uint8_t *) metadata_header, 
	 (uint8_t *) sce_info->metadata_header, sizeof(metadata_header_t));
  metadata_header_adjust_endianness(metadata_header);
  
  // Copy metadata sections
  if ((sce_info->metadata_header->section_count) ) {
    metadata_section_header_t *msh = (metadata_section_header_t *) (new_header + sce_info->metadata_section_header_offset);
    uint32_t cont = 0;
    while ( cont < sce_info->metadata_header->section_count ) {
      memcpy((uint8_t *)&msh[cont],
	     (uint8_t *)&sce_info->metadata_section_header[cont],
	     sizeof(metadata_section_header_t));
      metadata_section_header_adjust_endianness(&msh[cont]);
      ++cont;
    }
  }
  
  // Copy capabilites flags
  if ( (sce_info->sce_header->type) == SCE_TYPE_SELF ) {
    list_node_t *node = list_head(sce_info->capability_list);
    uint32_t offset = sce_info->capability_flags_offset;
    while  (node) {
      capability_flag_t *cap_flag = (capability_flag_t *) list_get(node);
      capability_flag_t *new = (capability_flag_t *)(new_header + offset);
      new->header.type = cap_flag->header.type;
      new->header.size = cap_flag->header.size;
      new->header.next = cap_flag->header.next;
      flag_header_adjust_endianness(&new->header);
      memcpy((uint8_t *)&new->payload, 
	     (uint8_t *)&cap_flag->payload, cap_flag->header.size - 16);
      offset += cap_flag->header.size;
      node = list_next(node);
    }
  }
}

static int generate_signature(sce_info_t *sce_info, keyset_t *keyset) {
  uint8_t hash[20];

  if (!keyset->priv_key || !keyset->pub_key) {
    return 0;
  }
  
  sha1(sce_info->output, 
       sce_info->metadata_header->signature_input_length, hash);

  ecdsa_set_curve(keyset->ctype);
  ecdsa_set_pub(keyset->pub_key);
  ecdsa_set_priv(keyset->priv_key);
  
  signature_t *signature = sce_info->signature;	
  ecdsa_sign(hash, signature->r, signature->s);

  memcpy(sce_info->output + sce_info->signature_offset, 
	 sce_info->signature, 
	 sizeof(signature_t));
  return 1;
}

static void calculate_section_hashes(sce_info_t *sce_info) {
  list_node_t *node = list_head(sce_info->sections_list);
  metadata_section_header_t *metadata_section_header = sce_info->metadata_section_header;
  
  while (node) {
    section_entry_t *section_entry = (section_entry_t *) list_get(node);
    uint32_t sha1_index = metadata_section_header->sha1_idx;
    uint32_t sha1_offset = 16 * sha1_index;
    uint8_t *sha1_ptr = sce_info->metadata_keys +  sha1_offset;
    memset(sha1_ptr, 0, 0x20);
	  
    uint32_t size = section_entry->size;
    uint8_t *ptr = section_entry->ptr;

    uint32_t hmac_key_offset = 16 * (sha1_index + 2);
    uint8_t *hmac_key_ptr = (uint8_t *) sce_info->metadata_keys +  hmac_key_offset;
    uint32_t hmac_key_size = 64;
    
    sha1_hmac(hmac_key_ptr, hmac_key_size,
	      ptr, size, sha1_ptr);
    
    node = list_next(node);
    ++metadata_section_header;
  }
}

int encrypt_metadata(sce_info_t *sce_info, keyset_raw_t *keyset_raw) {
  aes_context aes_ctx;
  uint8_t iv[16];  

  keyset_t *keyset = NULL;
  
  if ( keyset_raw ) {
    keyset = get_keyset_from_raw(keyset_raw);
  } else {
    keyset = find_keyset_from_header(sce_info);
    if ( !keyset )
      return 0;
  }
  
  calculate_section_hashes(sce_info);  
  memcpy((uint8_t *) sce_info->output + sce_info->metadata_keys_offset, 
	 sce_info->metadata_keys, 
	 sce_info->metadata_keys_size);
  
  generate_signature(sce_info, keyset);
  
  uint8_t *metadata_header = sce_info->output + sce_info->metadata_header_offset;
  
  aes_setkey_enc(&aes_ctx, sce_info->metadata_aes_keys->key, 128);
  memcpy(iv, sce_info->metadata_aes_keys->iv, sizeof(iv));  
  
  size_t nc_off = 0;
  uint8_t stream_buff[16];
  int len = sce_info->sce_header->header_len - sce_info->sce_header->metadata_offset - 0x60;
  aes_crypt_ctr(&aes_ctx, len, &nc_off, iv, stream_buff, metadata_header, metadata_header);  

  aes_setkey_enc(&aes_ctx, keyset->erk_key, 8 * keyset->erk_len);
  aes_crypt_cbc(&aes_ctx, AES_ENCRYPT, sizeof(metadata_t), keyset->riv_key,  
		(void *) sce_info->output + sce_info->metadata_aes_keys_offset,
		(void *) sce_info->output + sce_info->metadata_aes_keys_offset);

/*
  printf("despues de encriptar\n");
  print_metadata_key(stdout, sce_info->metadata_aes_keys);
  print_metadata_key(stdout, sce_info->output + sce_info->metadata_aes_keys_offset);

  aes_setkey_dec(&aes_ctx, keyset->erk_key, 8 * keyset->erk_len);
  aes_crypt_cbc(&aes_ctx, AES_DECRYPT, sizeof(metadata_t), keyset->riv_key,  
		(void *) sce_info->output + sce_info->metadata_aes_keys_offset,
		(void *) sce_info->output + sce_info->metadata_aes_keys_offset);

printf("offset: %x\n", sce_info->metadata_aes_keys_offset);
printf("despues de encriptar - 2\n");
 print_metadata_key(stdout, sce_info->metadata_aes_keys);
 print_metadata_key(stdout, sce_info->output + sce_info->metadata_aes_keys_offset);
*/	
  if (sce_info->sce_header->type == SCE_TYPE_SELF && sce_info->info_header->self_type == SELF_TYPE_NPDRM) {
    if (!npdrm_encrypt(sce_info))
      return 0;
  }

  return 1;
}

void self_encrypt_sections(sce_info_t *sce_info) {
  aes_context aes_ctx;
  list_node_t * node = list_head(sce_info->sections_list);
  metadata_section_header_t *msh = sce_info->metadata_section_header;
  while (node) {
    section_entry_t *entry = (section_entry_t *) list_get(node);
    if (msh->encrypted == METADATA_SECTION_ENCRYPTED_YES) {
      uint8_t iv[16];
      uint32_t iv_offset = msh->iv_idx * 16;
      uint32_t key_offset = msh->key_idx * 16;
      uint8_t *meta_iv =  sce_info->metadata_keys + iv_offset;
      uint8_t *meta_key =  sce_info->metadata_keys + key_offset;
      memcpy(iv, meta_iv, sizeof(iv));
      aes_setkey_enc(&aes_ctx, meta_key, 128);
      size_t nc_off = 0;
      uint8_t stream_buf[16];
      aes_crypt_ctr(&aes_ctx, entry->size, &nc_off, iv, stream_buf, entry->ptr, entry->ptr);
    }
    node = list_next(node);
    ++msh;
  }
}

int write_self(const char *output, sce_info_t *sce_info) {
  FILE *fp = fopen(output, "wb");
  
  if (!fp)
    return 0;

  // Write Self Header  
  fwrite(sce_info->output, 1, sce_info->sce_header->header_len, fp);
  
/*
printf("write_self\n");
printf("signature offset: %x\n", sce_info->signature_offset);

  aes_context aes_ctx;
    keyset_t *keyset = find_keyset_from_header(sce_info);

 print_metadata_key(stdout, sce_info->metadata_aes_keys);
  aes_setkey_dec(&aes_ctx, keyset->erk_key, 8 * keyset->erk_len);
  aes_crypt_cbc(&aes_ctx, AES_DECRYPT, sizeof(metadata_t), keyset->riv_key,  
		(void *) sce_info->output + sce_info->metadata_aes_keys_offset,
		(void *) sce_info->output + sce_info->metadata_aes_keys_offset);
 print_metadata_key(stdout, sce_info->output + sce_info->metadata_aes_keys_offset);
*/
  // Write all the sections
  list_node_t *node = list_head(sce_info->sections_list);
  while (node) {
    section_list_entry_t *raw_section = (section_list_entry_t *) list_get(node);
    fseek(fp, raw_section->offset, SEEK_SET);
    fwrite(raw_section->ptr, 1, raw_section->size, fp);
    node = list_next(node);
  }
  fclose(fp);
  return 1;
}

int decrypt_header(sce_info_t *sce_info, keyset_raw_t *keyset_override, metadata_t *metadata_override) {
  keyset_t *keyset;
  uint8_t riv[16];
  aes_context aes_ctx;
 
  if (metadata_override) {
    sce_info->metadata_aes_keys = metadata_override;
  } else {
    if (keyset_override) {
      keyset = get_keyset_from_raw(keyset_override);
    } else {
      keyset = find_keyset_from_header(sce_info);
      if (!keyset)
	return 0;
      if (verbose) {
	char version[6];
	int version_major = (keyset->version >> 48) & 0xFFFF;
	int version_minor = (keyset->version >> 32) & 0xFFFF;
	sprintf(version, "%02X.%02X", version_major, version_minor);
	printf("[*] Using keyset [%s 0x%04X %s]\n", keyset->name, keyset->revision, version);
      }
    }
    if (sce_info->sce_header->type == SCE_TYPE_SELF && sce_info->info_header->self_type == SELF_TYPE_NPDRM)  {
      if (!decrypt_with_klic(sce_info)) {
	return 0;
      }
    }
    aes_setkey_dec(&aes_ctx,  keyset->erk_key, keyset->erk_len * 8);
    memcpy(riv, keyset->riv_key, sizeof(riv));
    aes_crypt_cbc(&aes_ctx, AES_DECRYPT, sizeof(metadata_t), riv, 
		  (uint8_t *) sce_info->metadata_aes_keys, 
		  (uint8_t *) sce_info->metadata_aes_keys);		
  }
  metadata_t *metadata_aes = sce_info->metadata_aes_keys;
  if (metadata_aes->key_pad[0] != 0 || metadata_aes->iv_pad[0] != 0) {
    return 0;
  }
  
  aes_setkey_enc(&aes_ctx, metadata_aes->key, 128);
  size_t nc_off = 0;
  int len = sce_info->sce_header->header_len - sce_info->sce_header->metadata_offset - 0x60;
  aes_crypt_ctr(&aes_ctx, len, &nc_off, metadata_aes->iv, riv, 
		(uint8_t *) sce_info->metadata_header, 
		(uint8_t *) sce_info->metadata_header);  
  
  metadata_header_t *metadata_header = sce_info->metadata_header;
  metadata_header_adjust_endianness(metadata_header);
  
  if (metadata_header->section_count) {
    uint32_t count = 0;
    metadata_section_header_t *section = sce_info->metadata_section_header;
    while (count < metadata_header->section_count) {
      metadata_section_header_adjust_endianness(section);
      ++section;
      ++count;
    }
  }
  sce_info->metadata_decrypted = 1;
  sce_info->metadata_keys = (void *) sce_info->metadata_section_header + (metadata_header->section_count) * sizeof(metadata_section_header_t);
  sce_info->metadata_keys_size = (metadata_header->key_count) * 16;
  
  if (sce_info->sce_header->type == SCE_TYPE_SELF && metadata_header->signature_info_size) {
    sce_info->capability_list = list_alloc();
    capability_flag_t *capability = (void *) sce_info->metadata_keys + 16 * (metadata_header->key_count);
    flag_header_adjust_endianness(&capability->header);
    list_append(sce_info->capability_list, capability);
    uint32_t size = 0;
    while (capability->header.next && size < metadata_header->signature_info_size) {
      capability = (void *) capability + capability->header.size;
      size += capability->header.size;
      list_append(sce_info->capability_list, capability);
    }
    // After capability flags, comes the signature
    sce_info->signature = (void *) capability + capability->header.size;
  } else {
    sce_info->signature = (void *) sce_info->metadata_keys + (metadata_header->key_count) * 16;
  }
  return 1;
}

int decrypt_sections(sce_info_t *sce_info) {
  aes_context aes_ctx;
  metadata_header_t *metadata_header = sce_info->metadata_header;
  if (metadata_header->section_count) {
    metadata_section_header_t *section_header = sce_info->metadata_section_header;
    uint32_t i = 0;
    while (i < metadata_header->section_count) {
      if (section_header->encrypted == METADATA_SECTION_ENCRYPTED_YES) {
	if (section_header->key_idx > metadata_header->key_count ||
	    section_header->iv_idx > metadata_header->key_count ) {
	  printf("[*] Warning: Skipped decryption of section %03d (marked encrypted but key/iv index out of range)\n", i); 
	} else {
	  uint8_t *keys = sce_info->metadata_keys;
	  uint8_t iv[16];
	  uint8_t stream_buf[16];
	  memcpy(iv, keys + 16 * section_header->iv_idx, sizeof(iv));
	  aes_setkey_enc(&aes_ctx, keys + 16 * section_header->key_idx, 128);
	  size_t nc_off = 0;
	  aes_crypt_ctr(&aes_ctx, section_header->data_size, &nc_off, iv, stream_buf,
			(uint8_t *) sce_info->output + section_header->data_offset,
			(uint8_t *) sce_info->output + section_header->data_offset);
	  
#if 0
	  char buffer[255];
	  sprintf(buffer, "section-%i.bin", i);
	  printf("Seccion %i\n",i);
	  _write_buffer(buffer, (uint8_t *) sce_info->output + section_header->data_offset, section_header->data_size);
#endif
	}
      }
      ++section_header;
      ++i;
    }
    
  }
  return 1;
}

void print_header_data(FILE *out, sce_info_t *sce_info) {
  print_sce_header(out, sce_info->sce_header);
  if (sce_info->metadata_decrypted) {
    print_metadata_key(out, sce_info->metadata_aes_keys);
    print_metadata_header(out, sce_info->metadata_header);
    print_metadata_section_header(out, sce_info);
    print_sce_file_keys(out, sce_info);
  }
/*
#if 0
     _write_buffer("keys_dump", sce_info->metadata_keys, 
	sce_info->metadata_keys_size);
     _write_buffer("meta_dump", sce_info->metadata_aes_keys, 64);
#endif
*/
}

static void section_info_adjust_endianness(section_info_t *si) {
  si->offset = ES64(si->offset);
  si->size = ES64(si->size);
  si->compressed = ES32(si->compressed);
  si->unknown1 = ES32(si->unknown1);
  si->unknown2 = ES32(si->unknown2);
  si->encrypted = ES32(si->encrypted);
}

void filedigest_adjust_endianness(file_digest_t *digest) {
  digest->version = ES64(digest->version);
}

static void elf32_header_adjust_endianness(elf32_hdr_t *h) {
  h->type = ES16(h->type);
  h->machine = ES16(h->machine);
  h->version = ES32(h->version);
  h->entry_point = ES32(h->entry_point);
  h->program_header_offset = ES32(h->program_header_offset);
  h->section_header_offset = ES32(h->section_header_offset);
  h->flags = ES32(h->flags);
  h->header_size = ES16(h->header_size);
  h->program_header_entry_size = ES16(h->program_header_entry_size);
  h->program_header_count = ES16(h->program_header_count);
  h->section_header_entry_size = ES16(h->section_header_entry_size);
  h->section_header_count = ES16(h->section_header_count);
  h->sh_str_idx = ES16(h->sh_str_idx);
}

static void elf64_header_adjust_endianness(elf64_hdr_t *h) {
  h->type = ES16(h->type);
  h->machine = ES16(h->machine);
  h->version = ES32(h->version);
  h->entry_point = ES64(h->entry_point);
  h->program_header_offset = ES64(h->program_header_offset);
  h->section_header_offset = ES64(h->section_header_offset);
  h->flags = ES32(h->flags);
  h->header_size = ES16(h->header_size);
  h->program_header_entry_size = ES16(h->program_header_entry_size);
  h->program_header_count = ES16(h->program_header_count);
  h->section_header_entry_size = ES16(h->section_header_entry_size);
  h->section_header_count = ES16(h->section_header_count);
  h->sh_str_idx = ES16(h->sh_str_idx);
}

static void elf32_section_header_entry_adjust_endianness(elf32_section_header_t *e) {
  e->name_idx = ES32(e->name_idx);
  e->type = ES32(e->type);
  e->flags = ES32(e->flags);
  e->virtual_addr = ES32(e->virtual_addr);
  e->offset_in_file = ES32(e->offset_in_file);
  e->segment_size = ES32(e->segment_size);
  e->link = ES32(e->link);
  e->info = ES32(e->info);
  e->addr_align = ES32(e->addr_align);
  e->entry_size = ES32(e->entry_size);
}

static void elf64_section_header_entry_adjust_endianness(elf64_section_header_t *e) {
  e->name_idx = ES32(e->name_idx);
  e->type = ES32(e->type);
  e->flags = ES64(e->flags);
  e->virtual_addr = ES64(e->virtual_addr);
  e->offset_in_file = ES64(e->offset_in_file);
  e->segment_size = ES64(e->segment_size);
  e->link = ES32(e->link);
  e->info = ES32(e->info);
  e->addr_align = ES64(e->addr_align);
  e->entry_size = ES64(e->entry_size);
}

static void elf32_program_header_entry_adjust_endianness(elf32_program_header_t *e) {
  e->type = ES32(e->type);
  e->flags = ES32(e->flags);
  e->offset_in_file = ES32(e->offset_in_file);
  e->virtual_addr = ES32(e->virtual_addr);
  e->phys_addr = ES32(e->phys_addr);
  e->segment_size = ES32(e->segment_size);
  e->segment_mem_size = ES32(e->segment_mem_size);
  e->alignment = ES32(e->alignment);
}

static void elf64_program_header_entry_adjust_endianness(elf64_program_header_t *e) {
  e->type = ES32(e->type);
  e->flags = ES32(e->flags);
  e->offset_in_file = ES64(e->offset_in_file);
  e->virtual_addr = ES64(e->virtual_addr);
  e->phys_addr = ES64(e->phys_addr);
  e->segment_size = ES64(e->segment_size);
  e->segment_mem_size = ES64(e->segment_mem_size);
  e->alignment = ES64(e->alignment);
}

static void print_self_extended_header(FILE *out, self_extended_header_t *h) {
  fprintf(out, "[*] SELF Header:\n");
  fprintf(out, " Header Type         0x%016" PRIX64 "\n", h->header_type);
  fprintf(out, " App Info Offset     0x%016" PRIX64 "\n", h->appinfo_offset);
  fprintf(out, " ELF Offset          0x%016" PRIX64 "\n", h->elf_offset);
  fprintf(out, " PH Offset           0x%016" PRIX64 "\n", h->phdr_offset);
  fprintf(out, " SH Offset           0x%016" PRIX64 "\n", h->shdr_offset);
  fprintf(out, " Section Info Offset 0x%016" PRIX64 "\n", h->section_info_offset);
  fprintf(out, " SCE Version Offset  0x%016" PRIX64 "\n", h->sceversion_offset);
  fprintf(out, " Control Info Offset 0x%016" PRIX64 "\n", h->controlinfo_offset);
  fprintf(out, " Control Info Size   0x%016" PRIX64 "\n", h->controlinfo_size);
}

static void print_self_application_info(FILE *out, info_header_t *h) {
  char version[6];

  fprintf(out, "[*] Application Info:\n");

  const char *auth_id_name = id2name(h->authid, auth_ids, NULL);    
  if (auth_id_name) {
    fprintf(out, " Auth-ID   ");
    if ( raw_output == 1 )
      fprintf(out, "0x%016" PRIX64 " ",  h->authid);
    fprintf(out, "[%s]\n", auth_id_name);
  } else {
    fprintf(out, " Auth-ID   0x%016" PRIX64 "\n", h->authid);
  }
  
  const char *vendor_id_name = id2name(h->vendor_id, vendor_ids, NULL);  
  if (vendor_id_name) {
    fprintf(out, " Vendor-ID ");
    if ( raw_output == 1 )
      fprintf(out, "0x%08X ", h->vendor_id);
    
    fprintf(out, "[%s]\n", vendor_id_name);
  } else {
    fprintf(out, " Vendor-ID 0x%08X\n", h->vendor_id);
  }

  const char *self_type_name = id2name(h->self_type, self_long_name_types, NULL);  
  if (self_type_name) {
    fprintf(out, " SELF-Type [%s]\n", self_type_name);
  } else {
    fprintf(out, " SELF-Type 0x%08X\n", h->self_type);
  }
  int version_major = (h->version >> 48) & 0xFFFF;
  int version_minor = (h->version >> 32) & 0xFFFF;
  sprintf(version, "%02X.%02X", version_major, version_minor);
  fprintf(out, " Version   %s\n", version);  
}

static void print_self_sce_version(FILE *out, sdkversion_t *v) {
  fprintf(out, "[*] SCE Version:\n");
  fprintf(out, " Header Type 0x%08X\n", v->type);
  fprintf(out, " Present     [%s]\n", (v->present == 1)?"TRUE":"FALSE");
  fprintf(out, " Size        0x%08X\n", v->size);
  fprintf(out, " unknown_3   0x%08X\n", v->unknown3);
}

static void print_control_flag(FILE *out, control_flag_t *flag) {
  fprintf(out, "[*] Control Info\n");
  
  const char *controlflag_type_name = id2name(flag->header.type, controlflags_types, NULL);
  if (controlflag_type_name) {
    fprintf(out, " Type      %s\n", controlflag_type_name);
  } else {
    fprintf(out, " Type      0x%08X\n", flag->header.type);	
  }
  
  fprintf(out, " Size      0x%08X\n", flag->header.size);
  fprintf(out, " Next      [%s]\n", (flag->header.next)?"TRUE":"FALSE");
  
  if (flag->header.type == CONTROLFLAG_TYPE_CONTROL) {
    // 16 is header already shown
    _hexdump(out, " Flags", 0, (uint8_t *) &flag->control_flags, flag->header.size - 16, 0);
    
  } else if (flag->header.type == CONTROLFLAG_TYPE_FILEDIGEST) {
    if (flag->header.size == 48) {
      _hexdump(out, " Digest", 0, (uint8_t *)&flag->file_digest.digest1, 20, 0);
    } else if (flag->header.size == 64) {
      filedigest_adjust_endianness(&flag->file_digest);
      _hexdump(out, " Digest 1  ", 0, flag->file_digest.digest1, 20, 0);
      _hexdump(out, " Digest 2  ", 0, flag->file_digest.digest2, 20, 0);
      if (flag->file_digest.version) {				
	uint64_t version = flag->file_digest.version;
	
	fprintf(out, " FW Version %" PRId64 " [%02" PRId64 ".%02" PRId64 "]\n",
		version, version  / 10000, version  % 10000 / 100);
      }
    }
  } else if (flag->header.type == CONTROLFLAG_TYPE_NPDRM) {
    fprintf(out, " Magic        0x%08X [%s]\n", flag->npdrm.magic, (flag->npdrm.magic == 0x4E504400)?"OK":"ERROR");
    fprintf(out, " unknown_0    0x%08X\n", flag->npdrm.unknown0);
    fprintf(out, " Licence Type 0x%08X\n", flag->npdrm.license_type);
    fprintf(out, " App Type     0x%08X\n", flag->npdrm.type);
    fprintf(out, " ContentID    %s\n", flag->npdrm.content_id);
    _hexdump(out, " Random Pad  ", 0, flag->npdrm.hash, 16, 0);
    _hexdump(out, " CID_FN Hash ", 0, flag->npdrm.hash_iv, 16, 0);
    _hexdump(out, " CI Hash     ", 0, flag->npdrm.hash_xor, 16, 0);
    fprintf(out, " unknown_1    0x%016" PRIX64 "\n", flag->npdrm.unknown1);
    fprintf(out, " unknown_2    0x%016" PRIX64 "\n", flag->npdrm.unknown2);
  }	
}

static void print_capability_flag_payload(FILE *out, capability_flag_payload_t *p) {
  uint32_t flags = p->flags;
  if (flags & 1)
    fprintf(out, "0x01 ");
  if (flags & 2)
    fprintf(out, "0x02 ");
  if (flags & 4)
    fprintf(out, "0x04 ");
  if (flags & 8)
    fprintf(out, "REFTOOL ");
  if (flags & 0x10)
    fprintf(out, "DEBUG ");
  if (flags & 0x20)
    fprintf(out, "RETAIL ");
  if (flags & 0x40)
    fprintf(out, "SYSDBG ");
}

static void print_capability_flag(FILE *out, capability_flag_t *flag) {
  fprintf(out, "[*] Optional Header\n");
  const char *header_type = id2name(flag->header.type, capability_types, NULL);
  if (header_type) {
    fprintf(out, " Type      %s\n", header_type);
  } else {
    fprintf(out, " Type      0x%08X\n", flag->header.type);
  }
  fprintf(out, " Size      0x%08X\n", flag->header.size);
  fprintf(out, " Next      [%s]\n", (flag->header.next)?"TRUE":"FALSE");
  if (flag->header.type == 1) {
    capability_flag_payload_t *payload = &flag->payload;	
    if (raw_output == 1)
      _hexdump(out, " Flags", 0, (uint8_t *) payload,sizeof(capability_flag_payload_t), 0);
    capability_flag_payload_adjust_endianness(payload);
    fprintf(out, " unknown_3 0x%016" PRIX64 "\n", payload->unknown3);
    fprintf(out, " unknown_4 0x%016" PRIX64 "\n", payload->unknown4);
    fprintf(out, " Flags     0x%016" PRIX64 " [ ", payload->flags);
    print_capability_flag_payload(out, payload);
    fprintf(out, "]\n");
    fprintf(out, " unknown_6 0x%08X\n", payload->unknown6);
    fprintf(out, " unknown_7 0x%08X\n", payload->unknown7);
  }
}

static void print_elf32_header(FILE *out, elf32_hdr_t *h) {

  fprintf(out, "[*] ELF32 Header:\n");
  const char *header_type = id2name(h->type, elf_types, NULL);
  if (header_type) {
    printf(" Type                   [%s]\n", header_type);
  } else {
    printf(" Type                   0x%04X\n", h->type);
  }
  const char *machine_type = id2name(h->machine, machine_types, NULL);
  if (header_type) {
    printf(" Machine                [%s]\n", machine_type);
  } else {
    printf(" Machine                0x%04X\n", h->machine);
  }
  fprintf(out, " Version                0x%08X\n", h->version);
  fprintf(out, " Entry                  0x%08X\n", h->entry_point);
  fprintf(out, " Program Headers Offset 0x%08X\n", h->program_header_offset);
  fprintf(out, " Section Headers Offset 0x%08X\n", h->section_header_offset);
  fprintf(out, " Flags                  0x%08X\n", h->flags);
  fprintf(out, " Program Headers Count  %04d\n", h->program_header_count);
  fprintf(out, " Section Headers Count  %04d\n", h->section_header_count);
  fprintf(out, " SH String Index        %04d\n", h->sh_str_idx);
}

static void print_elf64_header(FILE *out, elf64_hdr_t *h) {
  fprintf(out, "[*] ELF64 Header:\n");

  const char *header_type = id2name(h->type, elf_types, NULL);
  if (header_type) {
    printf(" Type                   [%s]\n", header_type);
  } else {
    printf(" Type                   0x%04X\n", h->type);
  }
  const char *machine_type = id2name(h->machine, machine_types, NULL);
  if (header_type) {
    printf(" Machine                [%s]\n", machine_type);
  } else {
    printf(" Machine                0x%04X\n", h->machine);
  }
  fprintf(out, " Version                0x%08X\n", h->version);
  fprintf(out, " Entry                  0x%016" PRIX64 "\n", h->entry_point);
  fprintf(out, " Program Headers Offset 0x%016" PRIX64 "\n", h->program_header_offset);
  fprintf(out, " Section Headers Offset 0x%016" PRIX64 "\n", h->section_header_offset);
  fprintf(out, " Flags                  0x%08X\n", h->flags);
  fprintf(out, " Program Headers Count  %04d\n", h->program_header_count);
  fprintf(out, " Section Headers Count  %04d\n", h->section_header_count);
  fprintf(out, " SH String Index        %04d\n", h->sh_str_idx);
}

static void print_elf32_section_header(FILE *out, elf32_section_header_t *h, int index) {
  char permissions[] = "---";
  if ( h->flags )
    permissions[0] = 'W';
  if ( h->flags & 2 )
    permissions[1] = 'A';
  if ( h->flags & 4 )
    permissions[2] = 'E';
  fprintf(out, " %03d %04X ", index, h->name_idx);
  
  const char *entry_type = id2name(h->type, section_header_types, NULL);
  if (entry_type) {
    printf("%-13s ", entry_type);
  } else {
    printf("%08X      ", h->type);
  }
  fprintf(out,"%s   %05X   %05X  %05X %02X %05X %03d\n",
	  permissions,
	  h->virtual_addr,
	  h->offset_in_file,
	  h->segment_size,
	  h->entry_size,
	  h->addr_align,
	  h->link);
}

static void print_elf64_section_header(FILE *out, elf64_section_header_t *h, int index) {
  char permissions[] = "---";
  if (h->flags & 1)
    permissions[0] = 'W';
  if (h->flags & 2)
    permissions[1] = 'A';
  if (h->flags & 4)
    permissions[2] = 'E';
  
  fprintf(out, " %03d %04X ", index, h->name_idx);
  const char *entry_type = id2name(h->type, section_header_types, NULL);
  if (entry_type) {
    printf("%-13s ", entry_type);
  } else {
    printf("%08X      ", h->type);
  }
  fprintf(out,"%s   %08" PRIX64 "   %08" PRIX64 " %08" PRIX64 " %04" PRIX64 " %08" PRIX64 " %03d\n", permissions,
	  h->virtual_addr,
	  h->offset_in_file,
	  h->segment_size,
	  h->entry_size,
	  h->addr_align,
	  h->link);
}

static void print_elf32_program_header(FILE *out, elf32_program_header_t *e, int index) {
  char flags[] ="---";
  if (e->flags & 1) 
    flags[0] = 'X';
  if (e->flags & 2) 
    flags[1] = 'W';
  if (e->flags & 4) 
    flags[2] = 'R';
  fprintf(out, " %03d ", index);
  
  const char *entry_type = id2name(e->type, program_header_types, NULL);
  if (entry_type) {
    printf("%-7s  ", entry_type);
  } else {
    printf("0x%08X ", e->type);
  }
  fprintf(out, "%05X  %05X %05X %05X    %05X   %s   %05X\n",
	  e->offset_in_file,
	  e->virtual_addr,
	  e->phys_addr,
	  e->segment_size,
	  e->segment_mem_size,
	  flags,
	  e->alignment);
}


static void print_elf64_program_header(FILE *out, elf64_program_header_t *e, int index) {
  char flags1[] = "---";
  char flags2[] = "---";
  char flags3[] = "---";
  
  if (e->flags & 1) 
    flags1[0] = 'X';
  if (e->flags & 2) 
    flags1[1] = 'W';
  if (e->flags & 4) 
    flags1[2] = 'R';
  
  if ((e->flags >> 20) & 1)
    flags2[0] = 'X';
  if ((e->flags >> 20) & 2)
    flags2[1] = 'W';
  if ((e->flags >> 20) & 4)
    flags2[2] = 'R';
  
  if ((e->flags >> 24) & 1)
    flags3[0] = 'X';
  if ((e->flags >> 24) & 2)
    flags3[1] = 'W';
  if ((e->flags >> 24) & 4)
    flags3[2] = 'R';
  
  fprintf(out, " %03d ", index);
  
  const char *entry_type = id2name(e->type, program_header_types, NULL);
  if (entry_type) {
    printf("%-7s  ", entry_type);
  } else {
    printf("%08X ", e->type);
  }
  
  fprintf(out, "%08" PRIX64 " %08" PRIX64 " %08" PRIX64 " %08" PRIX64 " %08" PRIX64 " %s %s %s %08" PRIX64 "\n",
	  e->offset_in_file,
	  e->virtual_addr,
	  e->phys_addr,
	  e->segment_size,
	  e->segment_mem_size,
	  flags1,
	  flags2,
	  flags3,
	  e->alignment);
}

int print_self(FILE *out, sce_info_t *sce_info) {
  if (sce_info->sce_header->type != SCE_TYPE_SELF)
    return 0;
  
  print_self_extended_header(out, sce_info->extended_header);
  print_self_application_info(out, sce_info->info_header);
  if (sce_info->sdkversion) {
    print_self_sce_version(out, sce_info->sdkversion);
  }
  list_t *control_list = sce_info->control_flag_list;
  if (control_list) {
    list_node_t *node = list_head(control_list);
    while (node) {
      print_control_flag(out, (control_flag_t *) list_get(node));
      node = list_next(node);
    }
  }
  if (sce_info->metadata_decrypted) {		
    list_node_t *node = list_head(sce_info->capability_list);
    while (node) {
      capability_flag_t *flag = list_get(node);
      if (flag->header.type != 2)
	print_capability_flag(out, flag);
      node = list_next(node);
    }
  }
  uint32_t self_type = sce_info->info_header->self_type;
  elf32_hdr_t *elf32_header = (void *) sce_info->sce_header + sce_info->extended_header->elf_offset;
  if (self_type == SELF_TYPE_LDR || self_type == SELF_TYPE_ISO ||
      elf32_header->ident[EI_CLASS] == ELFCLASS32) {
    // Elf is 32 bits
    elf32_header_adjust_endianness(elf32_header);
    
    fprintf(stdout, "[*] Section Infos:\n");
    fprintf(stdout, " Idx Offset   Size     Compressed unk0     unk1     Encrypted\n");		
    if (elf32_header->program_header_count > 0) {
      section_info_t *si = sce_info->section_info;
      int i = 0;
      while (i < elf32_header->program_header_count) {
	section_info_adjust_endianness(si);
	fprintf(out, " %03d %08" PRIX64 " %08" PRIX64 " %s      %08X %08X %s\n",
		i, si->offset, si->size,
		(si->compressed == 2)?"[YES]":"[NO ]",
		si->unknown1, si->unknown2,
		(si->encrypted == 1)?"[YES]":"[NO ]");
	++si;
	++i;
      }			
    }
    print_elf32_header(out, elf32_header);
    
    fprintf(out, "[*] ELF32 Program Headers:\n");		
    fprintf(out, " Idx Type     Offset VAddr PAddr FileSize MemSize Flags Align\n");
    if (elf32_header->program_header_count > 0) {
      elf32_program_header_t *ph_entry = (void *) sce_info->output + sce_info->extended_header->phdr_offset;
      int i = 0;
      while (i < elf32_header->program_header_count) {
	elf32_program_header_entry_adjust_endianness(ph_entry);
	print_elf32_program_header(out, ph_entry, i);
	++ph_entry;
	++i;
      }
    }
    if (elf32_header->section_header_count > 0) {
      elf32_section_header_t *sh_entry = (void *) sce_info->output + sce_info->extended_header->shdr_offset;
      fprintf(out, "[*] ELF32 Section Headers:\n");
      fprintf(out, " Idx Name Type          Flags Address Offset Size  ES Align LK\n");
      int i = 0;
      while (i < elf32_header->section_header_count) {
	elf32_section_header_entry_adjust_endianness(sh_entry);
	print_elf32_section_header(out, sh_entry, i);
	++sh_entry;
	++i;
      }
    }	
  } else {
    // Elf is 64 bits
    elf64_hdr_t *elf64_header = (void *) sce_info->sce_header + sce_info->extended_header->elf_offset;
    elf64_header_adjust_endianness(elf64_header);
    
    fprintf(out, "[*] Section Infos:\n");
    fprintf(out, " Idx Offset   Size     Compressed unk0     unk1     Encrypted\n");
    if (elf64_header->program_header_count > 0) {
      section_info_t *si = sce_info->section_info;
      int i = 0;
      while (i < elf64_header->program_header_count) {
	section_info_adjust_endianness(si);
	fprintf(out, " %03d %08" PRIX64 " %08" PRIX64 " %s      %08X %08X %s\n",
		i, si->offset, si->size,
		(si->compressed == 2)?"[YES]":"[NO ]",
		si->unknown1, si->unknown2,
		(si->encrypted == 1)?"[YES]":"[NO ]");
	++si;
	++i;
      }			
    }
    print_elf64_header(out, elf64_header);
    
    fprintf(out, "[*] ELF64 Program Headers:\n");		
    fprintf(out, " Idx Type     Offset   VAddr    PAddr    FileSize MemSize  PPU SPU RSX Align\n");
    if (elf64_header->program_header_count > 0) {
      elf64_program_header_t *ph_entry = (void *) sce_info->output + sce_info->extended_header->phdr_offset;
      int i = 0;
      while (i < elf64_header->program_header_count) {
	elf64_program_header_entry_adjust_endianness(ph_entry);
	print_elf64_program_header(out, ph_entry, i);
	++ph_entry;
	++i;
      }
    }
    if (elf64_header->section_header_count > 0) {
      elf64_section_header_t *sh_entry = (void *) sce_info->output + sce_info->extended_header->shdr_offset;
      fprintf(out, "[*] ELF64 Section Headers:\n");
      fprintf(out, " Idx Name Type          Flags Address    Offset   Size     ES   Align    LK\n");
      int i = 0;
      while (i < elf64_header->section_header_count) {
	elf64_section_header_entry_adjust_endianness(sh_entry);
	print_elf64_section_header(out, sh_entry, i);
	++sh_entry;
	++i;
      }
    }			
  }
  return 1;
}

int write_elf(const char *filename, sce_info_t *sce_info) {
  if (sce_info->sce_header->type != SCE_TYPE_SELF)
    return 0;
	
  FILE *fp = fopen(filename, "wb");
  if (!fp)
    return 0;

  uint32_t self_type = sce_info->info_header->self_type;
  elf32_hdr_t *elf32_header = (void *) sce_info->sce_header + sce_info->extended_header->elf_offset;
  if (self_type == SELF_TYPE_LDR || 
      self_type == SELF_TYPE_ISO ||
      elf32_header->ident[EI_CLASS] == ELFCLASS32) {
    
    elf32_hdr_t elf32_header_copy;
    memcpy(&elf32_header_copy, elf32_header,sizeof(elf32_hdr_t));
    elf32_header_adjust_endianness(&elf32_header_copy);
    fwrite(elf32_header, sizeof(elf32_hdr_t), 1, fp);
    elf32_program_header_t *ph = (void *) sce_info->output + sce_info->extended_header->phdr_offset;
    fwrite(ph, sizeof(elf32_program_header_t), elf32_header_copy.program_header_count, fp);
    metadata_section_header_t *section_header = sce_info->metadata_section_header;
    if (sce_info->metadata_header->section_count) {
      uint32_t i = 0;
      while (i < sce_info->metadata_header->section_count) {
	if (section_header->type == METADATA_SECTION_HEADER_TYPE_PHDR) {
	  elf32_program_header_t *ph_section = ph + section_header->program_idx;
	  elf32_program_header_entry_adjust_endianness(ph_section);
	  fseek(fp, ph_section->offset_in_file, SEEK_SET);
	  fwrite((void *)sce_info->output + section_header->data_offset, 1, section_header->data_size, fp);
	}
	++i;
	++section_header;
      }
    }
    if (sce_info->extended_header->shdr_offset) {
      void *sh_ptr = (void *)(sce_info->output) + sce_info->extended_header->shdr_offset;
      fseek(fp, elf32_header_copy.section_header_offset, SEEK_SET);
      fwrite(sh_ptr, sizeof(elf32_section_header_t), elf32_header_copy.section_header_count, fp);			
    }
  } else {		
    elf64_hdr_t elf64_header_copy;
    
    elf64_hdr_t *elf64_header = (void *) sce_info->sce_header + sce_info->extended_header->elf_offset;
    memcpy(&elf64_header_copy, elf64_header, sizeof(elf64_hdr_t));
    elf64_header_adjust_endianness(&elf64_header_copy);
    fwrite(elf64_header, sizeof(elf64_hdr_t), 1, fp);
    elf64_program_header_t *ph = (void *) sce_info->output + sce_info->extended_header->phdr_offset;
    fwrite(ph, sizeof(elf64_program_header_t), elf64_header_copy.program_header_count, fp);
    
    if (sce_info->metadata_header->section_count) {
      uint32_t i = 0;
      metadata_section_header_t *section_header = sce_info->metadata_section_header;
      while (i < sce_info->metadata_header->section_count) {
	if (section_header->type == METADATA_SECTION_HEADER_TYPE_PHDR) {
	  if (section_header->compressed == SECTION_INFO_COMPRESSED_YES) {
	    elf64_program_header_t *ph_section = ph + section_header->program_idx;
	    elf64_program_header_entry_adjust_endianness(ph_section);
	    uint8_t *deflated = malloc(ph_section->segment_size);
	    
	    decompress((void *)sce_info->output + section_header->data_offset, 
		       section_header->data_size, 
		       deflated, ph_section->segment_size);
	    fseek(fp, ph_section->offset_in_file, SEEK_SET);
	    fwrite(deflated, 1, ph_section->segment_size, fp);
	    free(deflated);
	  } else {
	    elf64_program_header_t *ph_section = ph + section_header->program_idx;
	    elf64_program_header_entry_adjust_endianness(ph_section);
	    fseek(fp, ph_section->offset_in_file, SEEK_SET);
	    fwrite((void *)sce_info->output + section_header->data_offset, 1, section_header->data_size, fp);
	  }
	}
	++i;
	++section_header;
      }
    }
    if (sce_info->extended_header->shdr_offset) {
      void *sh_ptr = (void *)(sce_info->output) + sce_info->extended_header->shdr_offset;
      fseek(fp, elf64_header_copy.section_header_offset, SEEK_SET);
      fwrite(sh_ptr, sizeof(elf64_section_header_t), elf64_header_copy.section_header_count, fp);			
    }
  }

  fclose(fp);
  return 1;
}

int create_self_control_info(sce_info_t *sce_info, encrypt_options_t *opts) {
  static uint8_t empty_control_flags[] = { 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  
  static uint8_t control_flag_digest1[] = {
    0x62, 0x7C, 0xB1, 0x80, 
    0x8A, 0xB9, 0x38, 0xE3, 
    0x2C, 0x8C, 0x09, 0x17, 
    0x08, 0x72, 0x6A, 0x57, 
    0x9E, 0x25, 0x86, 0xE4 };
  
  int self_type = sce_info->info_header->self_type;
  if (self_type) {
    if (self_type <= SELF_TYPE_LDR || self_type == SELF_TYPE_NPDRM) {
      control_flag_t *cflag = (control_flag_t *) malloc(0x30u); // Control Flag Type 1
      cflag->header.type = CONTROLFLAG_TYPE_CONTROL;
      cflag->header.size = 0x30u;
      cflag->header.next = 1;
      memcpy(&cflag->control_flags, 
	     (opts->control_flags)?opts->control_flags:empty_control_flags,
	     sizeof(empty_control_flags));
      list_append(sce_info->control_flag_list, cflag);
    }
	
    if ( self_type > SELF_TYPE_LDR && self_type != SELF_TYPE_NPDRM )
      return 1;
    
    control_flag_t *cflag = (control_flag_t *) malloc(0x40u);
    cflag->header.type = CONTROLFLAG_TYPE_FILEDIGEST;
    cflag->header.size = 0x40u;
    cflag->header.next = (self_type == 8)?1:0;
    memcpy(cflag->file_digest.digest1, control_flag_digest1, sizeof (control_flag_digest1));
    memset(cflag->file_digest.digest2, 0, 20);
    
    sha1(sce_info->elf_data->image, 
	sce_info->elf_data->image_size, 
	cflag->file_digest.digest2);
    
    if ( self_type == SELF_TYPE_NPDRM ) {
      char version[5];
      uint32_t version_int;
      int version_major = (opts->fw_version >> 48) & 0xFFFF;
      int version_minor = (opts->fw_version >> 32) & 0xFFFF;
      sprintf(version, "%02X%02X", version_major, version_minor);
      sscanf(version, "%d", &version_int);
      cflag->file_digest.version = 100 * version_int; 
    } else {
      cflag->file_digest.version  = 0;
    }
    filedigest_adjust_endianness(&cflag->file_digest);
    list_append(sce_info->control_flag_list, cflag);
  }
  
  if (self_type == SELF_TYPE_NPDRM) {
    if (!opts->npdrm_info)
      return 0;
    control_flag_t *cflag = (control_flag_t *) malloc(0x90u);
    cflag->header.type = CONTROLFLAG_TYPE_NPDRM;
    cflag->header.size = 0x90;
    cflag->header.next = 0;
    if (!create_npd_controlflag_payload(opts->npdrm_info, &cflag->npdrm)) {
      free(cflag);
      return 0;
    }
    list_append(sce_info->control_flag_list, cflag);
  }
  return 1;
}

void fill_default_capability_flag(capability_flag_payload_t *p, int app_type) {
  switch ( app_type ) {
    case SELF_TYPE_LV0:
    case SELF_TYPE_LV1:
    case SELF_TYPE_LV2:
      p->flags = 0x7B;
      p->unknown6 = 0;
      break;
    case SELF_TYPE_APP:
      p->flags = 0x7B;
      p->unknown7 = 0x20000;
      p->unknown6 = 1;
      //p->unknown4 = 0x0300000001000000;
      break;
    case SELF_TYPE_ISO:
    case SELF_TYPE_LDR:
      p->flags = 0x78;
      break;
    case SELF_TYPE_NPDRM:
      p->flags = 0x3B;
      p->unknown7 = 0x2000;
      p->unknown6 = 1;
      break;
    default:
	break;
  }
  capability_flag_payload_adjust_endianness(p);
}

int create_self_optional_headers(sce_info_t *sce_info, encrypt_options_t *opts) {
  int app_type = sce_info->info_header->self_type;

  if (app_type && (app_type <= 6 || app_type == 8) ) {
    capability_flag_t *cflag = (capability_flag_t *) malloc(0x30);
    cflag->header.type = CAPABILITY_FLAG_TYPE_1;
    cflag->header.size = 0x30u;
    cflag->header.next = (app_type == SELF_TYPE_ISO);
    uint8_t *opts_flags = opts->capability_flags;
    if (opts_flags)
      memcpy(&cflag->payload, opts_flags, 0x20u);
    else
      fill_default_capability_flag(&cflag->payload, app_type);
    list_append(sce_info->capability_list, cflag);
  }
  if (app_type == SELF_TYPE_ISO) {
    capability_flag_t *cflag = (capability_flag_t *) malloc(0x110);
    cflag->header.type = CAPABILITY_FLAG_TYPE_2;
    cflag->header.size = 0x110;
    cflag->header.next = 0;
    memset(&cflag->payload, 0, 0x100u);
    list_append(sce_info->capability_list, cflag);
  }
  return 1;
}

static int build_self_32(sce_info_t *sce_info, encrypt_options_t *opts) {
  elf_data_t *elf_data = sce_info->elf_data;

  elf32_hdr_t *elf32_header = malloc(sizeof(elf32_hdr_t));
  if (elf32_header)
    memcpy(elf32_header, elf_data->image, sizeof(elf32_hdr_t));
  elf_data->header = (uint8_t *) elf32_header;
  elf_data->header_size = sizeof(elf32_hdr_t);

  elf32_header = malloc(sizeof(elf32_hdr_t));
  if (elf32_header)
    memcpy(elf32_header, elf_data->image,sizeof(elf32_hdr_t));
  elf32_header_adjust_endianness(elf32_header);

  int program_header_size = sizeof(elf32_program_header_t) * elf32_header->program_header_count;
  elf32_program_header_t *program_header = (elf32_program_header_t *) malloc(program_header_size);
  if (program_header) {
    memcpy(program_header, (void *) sce_info->elf_data->image + elf32_header->program_header_offset, program_header_size);
  }
  elf_data->program_header = (uint8_t *) program_header;
  elf_data->program_header_size = program_header_size;

  program_header = (elf32_program_header_t *) malloc(program_header_size);
  if (program_header) {
    memcpy(program_header, (void *) sce_info->elf_data->image + elf32_header->program_header_offset, program_header_size);
  }

  if (elf32_header->section_header_count) {
    int sectionheader_size = sizeof(elf32_section_header_t) * elf32_header->section_header_count;
    void *sh = malloc(sectionheader_size);
    if (sh) {
      memcpy(sh, (void *)sce_info->elf_data->image + elf32_header->section_header_offset, sectionheader_size);
    }
    elf_data->section_header = sh;
    elf_data->section_header_size = sectionheader_size;
  }

  sce_info->metadata_section_header = (metadata_section_header_t *) malloc(sizeof(metadata_section_header_t) * (elf32_header->program_header_count + 1));
  sce_info->section_info = (section_info_t *) malloc(sizeof(section_info_t) * elf32_header->program_header_count);
  int count = 0;
    while (count < elf32_header->program_header_count) {
      elf32_program_header_entry_adjust_endianness(program_header);
      uint32_t ph_size = program_header->segment_size;
      uint8_t *buff = malloc(ph_size);
      if (buff)
        memcpy(buff, sce_info->elf_data->image + program_header->offset_in_file, ph_size);

      append_section_entry_to_list(sce_info, buff, ph_size, 0);

      section_info_t *section_info = &sce_info->section_info[count];
      section_info->size = ph_size;
      section_info->offset = 0;
      int ph_type = program_header->type;
      section_info->encrypted = (ph_type == 1) || (ph_type == 0x700000A4) || (ph_type == 0x700000A8);

      section_info->compressed = SECTION_INFO_COMPRESSED_NO;
      section_info->unknown1 = 0;
      section_info->unknown2 = 0;

      metadata_section_header_t *metadata_section_header = &sce_info->metadata_section_header[count];
      metadata_section_header->type = METADATA_SECTION_HEADER_TYPE_PHDR;
      metadata_section_header->program_idx = count;
      metadata_section_header->hashed = 2;
      metadata_section_header->encrypted = 2 * ((ph_type == 1)) + 1;
      metadata_section_header->compressed = METADATA_SECTION_COMPRESSED_NO;
      ++count;
      ++program_header;
    }
  elf_data->self_program_header_count = elf32_header->program_header_count;
  elf_data->self_section_info_count = elf32_header->program_header_count;
  
  if (opts->add_section_headers == 1) {
    uint8_t *section_header = elf_data->section_header;
    if (section_header) {
      uint32_t sh_size = elf_data->section_header_size;
      uint8_t *sh_buff = malloc(elf_data->section_header_size);
      if ( sh_buff )
        memcpy(sh_buff, section_header, sh_size);
      append_section_entry_to_list(sce_info, sh_buff, sh_size, 0);	  
      metadata_section_header_t *msh = &sce_info->metadata_section_header[count];
      msh->type = METADATA_SECTION_HEADER_TYPE_SHDR;
      msh->program_idx = count + 1;
      msh->hashed = 2;
      msh->encrypted = METADATA_SECTION_ENCRYPTED_NO;
      msh->compressed = METADATA_SECTION_COMPRESSED_NO;
      ++count;
    }
  }
  sce_info->metadata_header->section_count = count;
  return 1;
}

static int build_self_64(sce_info_t* sce_info, encrypt_options_t *opts) {
  elf_data_t *elf_data = sce_info->elf_data;

  elf64_hdr_t *elf64_header = malloc(sizeof(elf64_hdr_t));
  if (elf64_header)
    memcpy(elf64_header, elf_data->image, sizeof(elf64_hdr_t));
  elf_data->header = (uint8_t *) elf64_header;
  elf_data->header_size = sizeof(elf64_hdr_t);

  elf64_header = malloc(sizeof(elf64_hdr_t));
  if (elf64_header)
    memcpy(elf64_header, elf_data->image, sizeof(elf64_hdr_t));
  elf64_header_adjust_endianness(elf64_header);
   
  int program_header_size = sizeof(elf64_program_header_t) * elf64_header->program_header_count;
  elf64_program_header_t *program_header = (elf64_program_header_t *) malloc(program_header_size);
  if (program_header) {
    memcpy(program_header, 
		(void *) sce_info->elf_data->image + elf64_header->program_header_offset, 
		program_header_size);
  }
  elf_data->program_header = (uint8_t *) program_header;
  elf_data->program_header_size = program_header_size;

  program_header = (elf64_program_header_t *) malloc(program_header_size);
  if (program_header) {
    memcpy(program_header, (void *) sce_info->elf_data->image + elf64_header->program_header_offset, program_header_size);
  }
  
  if (elf64_header->section_header_count) {
    int sectionheader_size = sizeof(elf64_section_header_t) * elf64_header->section_header_count;
    void *sh = malloc(sectionheader_size);
    if (sh) {
      memcpy(sh, (void *)sce_info->elf_data->image + elf64_header->section_header_offset, sectionheader_size);
    }
    elf_data->section_header = sh;
    elf_data->section_header_size = sectionheader_size;
  }

  sce_info->metadata_section_header = (metadata_section_header_t *) malloc(sizeof(metadata_section_header_t) * (elf64_header->program_header_count + 1));
  sce_info->section_info = (section_info_t *) malloc(sizeof(section_info_t) * elf64_header->program_header_count);

  uint64_t prev_offset = -1;
  int sections_skipped = 0;
  int j = 0;
  
  if (elf64_header->program_header_count) {
    while ( j < elf64_header->program_header_count) {
      elf64_program_header_entry_adjust_endianness(program_header);
      uint32_t type = program_header->type;

      section_info_t *section_info = &sce_info->section_info[j];
      section_info->size = program_header->segment_size;
      section_info->offset = 0;     
      section_info->encrypted = (type == 1) || (type == 0x700000A4) || (type == 0x700000A8);
      section_info->compressed = 1;
      section_info->unknown1 = 0;
      section_info->unknown2 = 0;

      // FIXME: Verify condition
      if ((opts->skip_sections != 1) || 
		(program_header->offset_in_file  != prev_offset && section_info->encrypted)) {
        uint32_t ph_size = program_header->segment_size; 
        uint8_t *buff_secc = malloc(ph_size);
        if ( buff_secc )
          memcpy(buff_secc, (uint8_t *) sce_info->elf_data->image + program_header->offset_in_file, ph_size);
	append_section_entry_to_list(sce_info, buff_secc, ph_size, 1);
	
        metadata_section_header_t *msh = &sce_info->metadata_section_header[j - sections_skipped];
        msh->type = METADATA_SECTION_HEADER_TYPE_PHDR;
        msh->program_idx = j - sections_skipped;
        msh->hashed = METADATA_SECTION_HASHED_YES;
        msh->encrypted = METADATA_SECTION_ENCRYPTED_YES;
        msh->compressed = METADATA_SECTION_COMPRESSED_NO;
      } else {
	const char *name = id2name(program_header->type, program_header_types, NULL);
        if ( !name ) {
          if (verbose)
            printf("[*] Skipped program header 0x%08X @ 0x%08" PRIX64 " (0x%08" PRIX64 ")\n", program_header->type, 
		   program_header->offset_in_file,
		   program_header->segment_size);		  
        } else {
	  if (verbose) 
            printf("[*] Skipped program header %-8s @ 0x%08" PRIX64 " (0x%08" PRIX64 ")\n", name, 
		   program_header->offset_in_file,
		   program_header->segment_size);		  
	}

	++sections_skipped;
      }
      prev_offset = program_header->offset_in_file;
      ++program_header;
      ++j;
    }   
  }  

  uint32_t idx = j - sections_skipped;
  elf_data->self_program_header_count = elf64_header->program_header_count;
  elf_data->self_section_info_count = j - sections_skipped;

  if (opts->add_section_headers == 1) {
    uint8_t *section_header = elf_data->section_header;
    if (section_header) {
      uint32_t sh_size = elf_data->section_header_size;
      uint8_t *sh_buff = malloc(elf_data->section_header_size);
      if ( sh_buff )
        memcpy(sh_buff, section_header, sh_size);
      append_section_entry_to_list(sce_info, sh_buff, sh_size, 0);
      metadata_section_header_t *msh = &sce_info->metadata_section_header[idx];
      msh->type = METADATA_SECTION_HEADER_TYPE_SHDR;
      msh->program_idx = idx + 1;
      msh->hashed = METADATA_SECTION_HASHED_YES;
      msh->encrypted = METADATA_SECTION_ENCRYPTED_NO;
      msh->compressed = METADATA_SECTION_COMPRESSED_NO;
      ++j;
    }
  }
  sce_info->metadata_header->section_count = j - sections_skipped;
  
  return 1;
}

int build_self(sce_info_t *sce_info, encrypt_options_t *opts) {
  int ret; 

  sce_info->sce_header->key_revision = opts->key_revision;
  
  sce_info->info_header->authid = opts->auth_id;
  sce_info->info_header->vendor_id = opts->vendor_id;
  sce_info->info_header->version = opts->app_version;
  sce_info->info_header->self_type = opts->self_type;

  if (!create_self_control_info(sce_info, opts) ) {
    printf("[*] Error: Could not create SELF control infos.\n");
    return 0;
  }

  if (!create_self_optional_headers(sce_info, opts)) {
      printf("[*] Error: Could not create SELF optional headers.\n");
      return 0;
  }  
  
  sce_info->sdkversion->type = 1;
  sce_info->sdkversion->present = 0;
  sce_info->sdkversion->size = sizeof(sdkversion_t); // 16
  sce_info->sdkversion->unknown3 = 0;
 
  if ( opts->self_type == SELF_TYPE_ISO || opts->self_type == SELF_TYPE_LDR )
    ret = build_self_32(sce_info, opts);
  else
    ret = build_self_64(sce_info, opts);
  return ret;
}
