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
 
#ifndef __SELF_H_
#define __SELF_H_

#include <stdint.h>
#include <stdio.h>

#include "list.h"
#include "keys.h"

#define SCE_MAGIC   0x53434500
#define NPDRM_MAGIC 0x4E504400


// ELF defines
#define EI_CLASS 4
#define ELFCLASS32 1
#define ELFCLASS64 2

#ifdef __cplusplus
extern "C" {
#endif

#define SCE_EXT_HEADER_TYPE_SELF   3
typedef struct { 
  uint64_t header_type;
  uint64_t appinfo_offset;
  uint64_t elf_offset;
  uint64_t phdr_offset;
  uint64_t shdr_offset;
  uint64_t section_info_offset;
  uint64_t sceversion_offset;
  uint64_t controlinfo_offset;
  uint64_t controlinfo_size;
  uint64_t padding;
} __attribute__((packed)) self_extended_header_t;

typedef struct {
  uint32_t magic;
  uint32_t version;
  uint16_t key_revision; //  flags
  uint16_t type;
  uint32_t metadata_offset;
  uint64_t header_len;
  uint64_t data_filesize;
} __attribute__((packed)) sce_hdr_t;

typedef struct {
  sce_hdr_t sce_header;
  self_extended_header_t ext_header;
} __attribute__((packed)) self_header_t;

typedef struct {
  uint64_t authid;
  uint32_t vendor_id;
  uint32_t self_type;
  uint64_t version; // 32 o 64 bits??
  uint64_t padding;
} __attribute__((packed)) info_header_t;

typedef struct {
  uint8_t ident[16];
  uint16_t type;
  uint16_t machine;
  uint32_t version;
  uint32_t entry_point;
  uint32_t program_header_offset;
  uint32_t section_header_offset;
  uint32_t flags;
  uint16_t header_size;
  uint16_t program_header_entry_size;
  uint16_t program_header_count;
  uint16_t section_header_entry_size;
  uint16_t section_header_count;
  uint16_t sh_str_idx;
} __attribute__((packed)) elf32_hdr_t;

typedef struct {
  uint8_t ident[16];
  uint16_t type;
  uint16_t machine;
  uint32_t version;
  uint64_t entry_point;
  uint64_t program_header_offset;
  uint64_t section_header_offset;
  uint32_t flags;
  uint16_t header_size;
  uint16_t program_header_entry_size;
  uint16_t program_header_count;
  uint16_t section_header_entry_size;
  uint16_t section_header_count;
  uint16_t sh_str_idx;
} __attribute__((packed)) elf64_hdr_t;

typedef struct {
  uint32_t type;
  uint32_t flags;
  uint64_t offset_in_file;
  uint64_t virtual_addr;
  uint64_t phys_addr;
  uint64_t segment_size;
  uint64_t segment_mem_size;
  uint64_t alignment;
} __attribute__((packed)) elf64_program_header_t;

typedef struct {
  uint32_t type;
  uint32_t offset_in_file;
  uint32_t virtual_addr;
  uint32_t phys_addr;
  uint32_t segment_size; // size in file
  uint32_t segment_mem_size; // size in memory
  uint32_t flags;
  uint32_t alignment;
} __attribute__((packed)) elf32_program_header_t;

typedef struct {
  uint32_t name_idx;
  uint32_t type;
  uint64_t flags;
  uint64_t virtual_addr;
uint64_t offset_in_file;
  uint64_t segment_size;
  uint32_t link;
  uint32_t info;
  uint64_t addr_align;
  uint64_t entry_size;
} __attribute__((packed)) elf64_section_header_t;

typedef struct {
  uint32_t name_idx;
  uint32_t type;
  uint32_t flags;
  uint32_t virtual_addr;
  uint32_t offset_in_file;
  uint32_t segment_size;
  uint32_t link;
  uint32_t info;
  uint32_t addr_align;
  uint32_t entry_size;
} __attribute__((packed)) elf32_section_header_t;

#define SECTION_INFO_COMPRESSED_YES 2
#define SECTION_INFO_COMPRESSED_NO  1

#define SECTION_INFO_ENCRYPTED_YES  1
#define SECTION_INFO_ENCRYPTED_NO   0


typedef struct {
  uint64_t offset;
  uint64_t size;
  uint32_t compressed; // 2=compressed
  uint32_t unknown1;
  uint32_t unknown2;
  uint32_t encrypted; // 1=encrypted
} __attribute__((packed)) section_info_t;


typedef struct {
  uint8_t *ptr;
  uint32_t size;
  uint32_t offset;
  uint32_t compressed; 
} __attribute__((packed)) section_list_entry_t;

typedef struct {
  uint32_t type;
  uint32_t present;
  uint32_t size;
  uint32_t unknown3;
} __attribute__((packed)) sdkversion_t;

#define CONTROLFLAG_TYPE_CONTROL     1
#define CONTROLFLAG_TYPE_FILEDIGEST  2
#define CONTROLFLAG_TYPE_NPDRM       3

typedef struct {
      uint8_t digest1[20];
      uint8_t digest2[20];
      uint64_t version;
} file_digest_t;

typedef struct {
        uint32_t magic;
        uint32_t unknown0;
        uint32_t license_type;
        uint32_t type;
        uint8_t content_id[0x30];
        uint8_t hash[0x10];
        uint8_t hash_iv[0x10];
        uint8_t hash_xor[0x10];
        uint64_t unknown1;
		uint64_t unknown2;
} npdrm_info_t;

typedef struct {
  uint32_t type;
  uint32_t size;
  uint64_t next;
} __attribute__ ((packed)) flag_header_t;

typedef struct {
  uint64_t unknown3;
  uint64_t unknown4;
  uint64_t flags;
  uint32_t unknown6;
  uint32_t unknown7;
} __attribute__((packed)) capability_flag_payload_t;

typedef struct {
  flag_header_t header;
  capability_flag_payload_t payload;
} __attribute__((packed)) capability_flag_t;

#define CAPABILITY_FLAG_TYPE_1 1
#define CAPABILITY_FLAG_TYPE_2 2

typedef struct {
  // type is:  1==control flags; 2==file digest
  flag_header_t header;
  union {
    // type 1
    struct {
	  uint32_t unknown[8];
/*	
      uint64_t control_flags;
      uint8_t padding[32];
*/	  
    } control_flags;

    // type 2
    file_digest_t file_digest;
    // type 3
    npdrm_info_t npdrm;

  };
} __attribute__((packed)) control_flag_t;


typedef struct {
  //uint8_t ignore[32];
  uint8_t key[16];
  uint8_t key_pad[16];
  uint8_t iv[16];
  uint8_t iv_pad[16];
} __attribute__((packed)) metadata_t;

typedef struct {
  uint64_t signature_input_length;
  uint32_t unknown0;
  uint32_t section_count;
  uint32_t key_count;
  uint32_t signature_info_size;
  uint32_t unknown1;
  uint32_t unknown2;
} __attribute__((packed)) metadata_header_t;

#define METADATA_INFO_UNKNOWN_SIZE 0x20

#define METADATA_SECTION_HASHED_YES 2
#define METADATA_SECTION_HASHED_NO 1 // ??

#define METADATA_SECTION_ENCRYPTED_YES 3
#define METADATA_SECTION_ENCRYPTED_NO  1

#define METADATA_SECTION_COMPRESSED_YES  2
#define METADATA_SECTION_COMPRESSED_NO  1

#define METADATA_SECTION_HEADER_TYPE_PHDR 2
#define METADATA_SECTION_HEADER_TYPE_SHDR 1

typedef struct {
  uint64_t data_offset;
  uint64_t data_size;
  uint32_t type; // 1 = shdr, 2 == phdr
  uint32_t program_idx;
  uint32_t hashed;
  uint32_t sha1_idx;
  uint32_t encrypted; // 3=yes; 1=no
  uint32_t key_idx;
  uint32_t iv_idx;
  uint32_t compressed; // 2=yes; 1=no
} __attribute__((packed)) metadata_section_header_t;

typedef struct {
  uint8_t sha1[20];
  uint8_t padding[12];
  uint8_t hmac_key[64];
} __attribute__((packed)) section_hash_t;

typedef struct {
  uint8_t r[21];
  uint8_t s[21];
  uint8_t padding[6];
} __attribute__((packed)) signature_t;


typedef struct {
  uint8_t *data;
  uint64_t size;
  uint64_t offset;
} SELF_SECTION;

typedef struct {
  uint8_t *image;
  uint32_t image_size;
  uint8_t *header;
  uint32_t header_size;
  uint8_t *program_header;
  uint32_t program_header_size;
  uint8_t *section_header;
  uint32_t section_header_size;
  uint32_t self_program_header_count;
  uint32_t self_section_info_count;
} elf_data_t;

typedef struct sce_info_struct {
	uint8_t *output; // RAW POINTER ???
	sce_hdr_t *sce_header; // SELF HEADER ???
	self_extended_header_t *extended_header;
	info_header_t *info_header;
	section_info_t *section_info;
	sdkversion_t *sdkversion;
	list_t *control_flag_list;
	list_t *capability_list;	
	metadata_t *metadata_aes_keys;
	metadata_header_t *metadata_header;
	metadata_section_header_t *metadata_section_header;
	uint8_t *metadata_keys;
	uint32_t metadata_keys_size;
	signature_t *signature;
	int metadata_decrypted;

	// offsets
	uint32_t sce_header_offset;
	uint32_t extended_header_offset;
	uint32_t info_header_offset;
	uint32_t elf_header_offset;
	uint32_t elf_program_header_offset;
	uint32_t section_info_offset;
	uint32_t sdk_version_offset;
	uint32_t control_flags_offset;
	uint32_t capability_flags_offset;
	uint32_t metadata_aes_keys_offset;
	uint32_t metadata_header_offset;
	uint32_t metadata_section_header_offset;
	uint32_t metadata_keys_offset;
	uint32_t signature_offset;
	uint32_t end_of_header;
	
	elf_data_t *elf_data;
	list_t *sections_list;
} sce_info_t;

typedef struct {
	uint8_t *ptr;
	uint32_t size;
	uint32_t offset;
	uint32_t compressed;
} section_entry_t;

void compress_sections(sce_info_t *sce_info);
void build_self_header(sce_info_t *sce_info);
sce_info_t *create_self_info(uint8_t *header, int size);
int decrypt_sections(sce_info_t *sce_info);
int decrypt_header(sce_info_t *sce_info, keyset_raw_t *keyset_override, metadata_t *metadata_override);
int encrypt_metadata(sce_info_t *sce_info, keyset_raw_t *keyset_raw);
void filedigest_adjust_endianness(file_digest_t *digest);
sce_info_t *process_sce_file(self_header_t *scefile);
int write_elf(const char *filename, sce_info_t *sce_info);
void self_encrypt_sections(sce_info_t *sce_info);
void self_fill_header(sce_info_t *sce_info);
int write_self(const char *output, sce_info_t *sce_info);

void print_header_data(FILE *out, sce_info_t *sce_info);
int print_self(FILE *out, sce_info_t *sce_info);

keyset_t *find_keyset_from_header(sce_info_t *sce_info);

#ifdef __cplusplus
}
#endif

#endif
