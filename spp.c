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
#include "spp.h"

static void spp_header_adjust_endianness(spp_header_t *spp_header) {
  spp_header->unk1 = ES16(spp_header->unk1);
  spp_header->format_version = ES16(spp_header->format_version);
  spp_header->unk3 = ES32(spp_header->unk3);
  spp_header->unk4 = ES32(spp_header->unk4);
  spp_header->unk5 = ES64(spp_header->unk5);
  spp_header->entry_count = ES32(spp_header->entry_count);
  spp_header->unk7 = ES32(spp_header->unk7);
}
  
static void adjust_endianness_spp_entry(spp_entry_t *entry) {
  entry->type = ES32(entry->type);
  entry->size = ES32(entry->size);
  entry->lpar_authid = ES64(entry->lpar_authid);
  entry->prog_authid = ES64(entry->prog_authid);
}

void print_spp_header(FILE *out, spp_header_t *h) {
  fprintf(out, "[*] SPP Header:\n");
  fprintf(out, " unk1        0x%04X\n", h->unk1);
  fprintf(out, " unk2        0x%04X\n", h->format_version);
  fprintf(out, " SPP Size    0x%08X\n", h->spp_size);
  fprintf(out, " unk3        0x%08X\n", h->unk3);
  fprintf(out, " unk4        0x%08X\n", h->unk4);
  fprintf(out, " unk5        0x%016" PRIX64 "\n", h->unk5);
  fprintf(out, " Entry Count 0x%08X\n", h->entry_count);
  fprintf(out, " unk7        0x%08X\n", h->unk7);
}

void print_spp(FILE *out, sce_info_t *sce_info) {

  metadata_section_header_t *metadata_section = sce_info->metadata_section_header;  
  spp_header_t *spp_header = (void *)sce_info->output + metadata_section->data_offset; 
  spp_header_adjust_endianness(spp_header);
  print_spp_header(out, spp_header);

  ++metadata_section;
  spp_entry_t *entry = (spp_entry_t *) ((void *) sce_info->output + metadata_section->data_offset);
  
  uint32_t i = 0;
  while (i < spp_header->entry_count) {
    adjust_endianness_spp_entry(entry);
    fprintf(out, "[*] SPP Entry %02d:\n", i);
    fprintf(out, " Size            0x%08X\n", entry->size);
    fprintf(out, " Type            0x%08X\n", entry->type);
    fprintf(out, " LPAR Auth-ID    0x%016" PRIX64 "\n", entry->lpar_authid);
    fprintf(out, " Program Auth-ID 0x%016" PRIX64 "\n", entry->prog_authid);
    fprintf(out, " Name            %s\n", entry->name);
    _hexdump(out, " Data", 0, &entry->data, entry->size - SPP_HEADER_NO_DATA_LEN, 1);
    entry = (void *) entry + entry->size;
    ++i; 
  }
}

int write_spp(const char *filename, sce_info_t *sce_info) {
  uint8_t *data = sce_info->output + sce_info->metadata_section_header->data_offset; 
  uint32_t len = sce_info->metadata_section_header[0].data_size + 
            sce_info->metadata_section_header[1].data_size;

  return _write_buffer(filename, data, len);
}
