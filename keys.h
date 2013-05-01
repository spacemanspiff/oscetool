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

#ifndef __KEYS_H_
#define __KEYS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"
#include "util.h"

typedef struct _keyset {
  char *name;
  uint32_t type;
  uint32_t revision; // or uint64_t ???
  uint64_t version;
  uint32_t self_type;
  uint32_t erk_len;
  uint8_t *erk_key;
  uint32_t riv_len;
  uint8_t *riv_key;
  uint8_t *pub_key;
  uint8_t *priv_key;
  uint8_t ctype;
} keyset_t;

typedef struct _curve {
  uint8_t p[20];
  uint8_t a[20];
  uint8_t b[20];
  uint8_t N[21];
  uint8_t Gx[20];
  uint8_t Gy[20];
} curve_t;

typedef struct _curve_vsh {
  uint8_t p[20];
  uint8_t a[20];
  uint8_t b[20];
  uint8_t N[20];
  uint8_t Gx[20];
  uint8_t Gy[20];
} curve_vsh_t;

// Keyset from Commandline
typedef struct _keyset_raw {
  uint8_t erk[32];
  uint8_t riv[16];
  uint8_t pub[40];
  uint8_t priv[21];
  uint8_t curve;
} keyset_raw_t;

typedef struct {
  uint8_t unk1[0x10]; //version, license type and user number
  uint8_t titleid[0x30]; //Content ID
  uint8_t padding[0xC]; //Padding for randomness
  uint32_t actdat_index; //Key index on act.dat between 0x00 and 0x7F
  uint8_t key[0x10]; //encrypted klicensee
  uint64_t unk2; //timestamp??
  uint64_t unk3; //Always 0
  uint8_t rs[0x28];
} rif_t;

typedef struct {
  uint8_t unk1[0x10]; //Version, User number
  uint8_t key_table[0x800]; //Key Table
  uint8_t unk2[0x800];
  uint8_t signature[0x28];
} actdat_t;

extern curve_t *loader_curves;
extern curve_vsh_t *vsh_curves;

void print_keysets(FILE *fp);
int load_keysets(const char *filename);

int load_ldr_curves(const char *filename);
int load_vsh_curves(const char *filename);

//keyset_t *find_keyset_from_header(sce_info_t *sce_info);
keyset_t *find_keyset_by_name(const char *name);
uint8_t *find_key_by_name(const char *name);

int decrypt_klicensee(const uint8_t *title_id, uint8_t *klic);

keyset_t *get_keyset_from_raw(keyset_raw_t *raw);

curve_t *get_vsh_curve(uint32_t type);

#ifdef __cplusplus
}
#endif

#endif
