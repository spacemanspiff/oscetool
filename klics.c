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
#include "types.h"
#include "list.h"
#include "util.h" 
#include "klics.h"

static list_t * klics_list = 0;

uint8_t *find_klicensee(const char *content_id) {
  if (!klics_list)
    return 0;
  list_node_t *node = list_head(klics_list);
  while (node) {
    klic_entry_t *entry = (klic_entry_t *) list_get(node);
    if (strcmp(content_id, entry->content_id) == 0) {
	return entry->klicensee;
    }
    node = list_next(node);
  }
  return NULL;
}

int load_klicensees(const char *filename) {
  klics_list = list_alloc();

  FILE *fp = fopen(filename, "r");
  if (!fp) {
	return 0;
  }

  while (!feof(fp)) {
    char line[CONFIG_MAX_LINE_SIZE];
    read_line(line, CONFIG_MAX_LINE_SIZE, fp);
    if (strlen(line) < 32)
      continue;

    char *pos = line;
    int len = 32;
    int valid = 1;
    while (len-- && valid) {
	valid = valid_hex_digit(*pos);
	++pos;
    }
    if (!valid) {
	continue;
    }
    if (*pos != ' ') {
	continue;
    }
    *pos = 0;
    ++pos;
    uint8_t *klic = x_to_u8_buffer(line);
    char *start = NULL;
    int used = 0;
    while (*pos) {
    if (*pos == '[')
      start = pos + 1;
      if (*pos == ']') {
        if (start) {
          used = 1;
          *pos = '\0';
	  klic_entry_t *entry = malloc(sizeof(klic_entry_t));
	  entry->content_id = strdup(start);
	  entry->klicensee = klic;
          list_append(klics_list, entry);
          start = NULL;
        }
      }
      ++pos;
    }
    if (!used) {
	free(klic);
    }
  }
  return 1;
}
