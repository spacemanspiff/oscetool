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
 
 #include "rvk.h"

#include "util.h"
#include "ids.h"

static void revoke_list_header_adjust_endianness(revoke_list_header_t *h) {
  h->type = ES32(h->type);
  h->unk1 = ES32(h->unk1);
  h->prg.version = ES64(h->prg.version);
  h->entry_count = ES32(h->entry_count);
}

static void print_revoke_list_header(FILE *out, revoke_list_header_t *h) {
  fprintf(out, "[*] Revoke List Header:\n");
  fprintf(out, " type_0      0x%08X\n", h->type);
  fprintf(out, " type_1      0x%08X\n", h->unk1);
  
  if ( h->type == RVK_LIST_TYPE0_PROGRAM ) {
    char version[6];
    int version_major = (h->prg.version >> 48) & 0xFFFF;
    int version_minor = (h->prg.version >> 32) & 0xFFFF;
    sprintf(version, "%02X.%02X", version_major, version_minor);
    fprintf(out, " Version     %s\n", version);
  } else {
    fprintf(out, " Opaque      0x%016" PRIX64 "\n", h->pkg.unk0);
  }
  fprintf(out, " Entry Count 0x%08X\n", h->entry_count);
}


static void revoke_entry_adjust_endianness(revoke_entry_t *entry) {
  entry->type = ES32(entry->type);
  entry->flags = ES32(entry->flags);
  entry->check = ES64(entry->check);
  entry->auth_id = ES64(entry->auth_id);
  entry->mask = ES64(entry->mask);
}

static void print_revoke_list_entry(FILE *out, revoke_entry_t *entry) {
  const char *self_type_name = id2name(entry->type, self_long_name_types, NULL);
  if (self_type_name) {
    fprintf(out, " %-19s ", self_type_name);
  } else {
    fprintf(out, " 0x%08X          ", entry->type);
  }  
  
  const char *auth_id_flag_name = id2name(entry->flags, auth_id_flags, NULL);
  if (auth_id_flag_name) {
    fprintf(out, "%-2s       ", auth_id_flag_name);
  } else {
    fprintf(out, "%08X ", entry->flags);
  }
  
  char check[6];
  int check_major = (entry->check >> 48) & 0xFFFF;
  int check_minor = (entry->check >> 32) & 0xFFFF;
  sprintf(check, "%02X.%02X", check_major, check_minor);  
  fprintf(stdout, "%s   ", check); 
  
  const char *auth_id_name = id2name(entry->auth_id, auth_ids, NULL);
  if (auth_id_name) {
    fprintf(out, "%-16s ", auth_id_name);
  } else {
    fprintf(out, "%016" PRIX64 " ", entry->auth_id);
  }

  fprintf(out, "%016" PRIX64 " ", entry->mask);
  fprintf(out, "\n");
}
		
void print_rvk(FILE *out, sce_info_t *sce_info) {
  metadata_section_header_t *metadata_section = sce_info->metadata_section_header;  
  
  revoke_list_header_t *revoke_list_header =
    (revoke_list_header_t *)((void *)sce_info->output + metadata_section->data_offset);
  revoke_list_header_adjust_endianness(revoke_list_header);
  
  print_revoke_list_header(out, revoke_list_header);
  ++metadata_section;
  
  if (revoke_list_header->type == RVK_LIST_TYPE0_PROGRAM) {
    revoke_entry_t *entry = (revoke_entry_t *) ((void *)sce_info->output + metadata_section->data_offset);
    
    fprintf(out, "[*] Program Revoke List Entries:\n");
    fprintf(out, " Type                Check    Version Auth-ID/unk_3    Mask\n");
    uint32_t i = 0;
    while (i < revoke_list_header->entry_count) {
      revoke_entry_adjust_endianness(entry);
      print_revoke_list_entry(out, entry);
      ++i;
      ++entry;
    }
  } else if (revoke_list_header->type == RVK_LIST_TYPE0_PACKAGE) {
    fprintf(stdout, "[*] Package Revoke List Entries:\n");
    revoke_entry_t *entry = (revoke_entry_t *) ((void *)sce_info->output + metadata_section->data_offset);
    uint32_t i = 0;
    while (i < revoke_list_header->entry_count) {
      _hexdump(out, " ent", 32*i, (uint8_t *) entry, sizeof(revoke_entry_t), 1);
      ++i;
      ++entry;
    }
  } 
}

int write_rvk(const char *filename, sce_info_t *sce_info) {
  uint8_t *data = (void *) sce_info->output + sce_info->metadata_section_header->data_offset; 
  uint32_t len = sce_info->metadata_section_header[0].data_size + 
            sce_info->metadata_section_header[1].data_size;

  return _write_buffer (filename, data, len);
}
