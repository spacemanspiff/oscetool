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
#include "patches.h"

#include "backend.h"

#include "self.h"

static int patch_sys_process_param(sys_process_param_t *section, uint32_t sdk_version) {
  if (section->size < 0x10)
    return 0;
  uint32_t magic = ES32(section->magic);

  if (magic != SYS_PROCESS_SPAWN_MAGIC &&
      magic != SYS_PROCESS_SPAWN_MAGIC_ALT)
    return 0;

  if (section->sdk_version == ES32(sdk_version)) {
    if (verbose)
      printf("[*] Warning: SDK Version on sys_process_param does not need patching.\n");
  } else {
    section->sdk_version = ES32(sdk_version);
    if (verbose)
      printf("[*] SDK Version on sys_process_param patched (%08X).\n", sdk_version);
  }
  return 1;
}

int patch_elf(elf_data_t *elf_data, patch_options_t *opts) {
  elf32_hdr_t *h = (elf32_hdr_t *) elf_data->image;  
  uint32_t i;
  if (!opts)
    return 1;
  if (opts->sdk_version) {
    if (h->ident[EI_CLASS] == ELFCLASS32) {
      uint32_t ph_offset = ES32(h->program_header_offset);
      elf32_program_header_t *ph = (elf32_program_header_t *) (elf_data->image + ph_offset);
      for (i = 0; i < elf_data->self_program_header_count; ++i) {
        uint32_t type = ES32(ph[i].type);
        if (type == PH_TYPE_SYS_PROCESS_SPAWN) {
          uint32_t offset= ES32(ph[i].offset_in_file);
          if (offset) {
            sys_process_param_t *section = (sys_process_param_t *) (elf_data->image + offset);
            patch_sys_process_param(section, opts->sdk_version); 
          }
        }
      }
    } else {
      elf64_hdr_t *h64 = (elf64_hdr_t *) elf_data->image;
      uint64_t ph_offset = ES64(h64->program_header_offset);
      elf64_program_header_t *ph = (elf64_program_header_t *) (elf_data->image + ph_offset);
      uint16_t  program_header_count = ES16(h64->program_header_count);
      for (i = 0; i < program_header_count; ++i) {
        uint32_t type = ES32(ph[i].type);
        if (type == PH_TYPE_SYS_PROCESS_SPAWN) {
          uint64_t offset = ES64(ph[i].offset_in_file);
          if (offset) {
            sys_process_param_t *section = (sys_process_param_t *) (elf_data->image + offset);
            patch_sys_process_param(section, opts->sdk_version); 
          }
        }
      }
    }
  }
  return 1;
}
