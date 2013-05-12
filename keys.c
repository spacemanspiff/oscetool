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
 
#include "keys.h"
#include "self.h"
#include "list.h"
#include "util.h"

#include "ids.h" 

#include "global.h"
#include "backend.h"

#include "npdrm.h"

#include "polarssl/aes.h"

#define LOADER_CURVES_NUM 64
#define VSH_CURVES_NUM 3

static list_t *keyset_list;
curve_t *loader_curves;
curve_vsh_t *vsh_curves;

static void add_key_to_keyset(const char *name, const char *value, keyset_t *keyset) {
  if (strcmp(name, "type") == 0) {
    if ( strcmp(value, "SELF") == 0) {
      keyset->type = SCE_TYPE_SELF;
    } else if (strcmp(value, "RVK") == 0) {
      keyset->type = SCE_TYPE_RVK;
    } else if (strcmp(value, "PKG") == 0) {
      keyset->type = SCE_TYPE_PKG;
    } else if (strcmp(value, "SPP") == 0) {
      keyset->type = SCE_TYPE_SPP;
    } else if (strcmp(value, "OTHER") == 0) {
      keyset->type = SCE_TYPE_OTHER;
    } else {
      printf("[*] Error: Unknown type '%s'.\n", value);
    }
  } else if (strcmp(name, "revision") == 0) {
    keyset->revision = x_to_u64(value);
  } else if (strcmp(name, "version") == 0) {
    keyset->version = x_to_u64(value);
  } else if (strcmp(name, "self_type") == 0) {
    if (strcmp(value, "LV0") == 0) {
      keyset->self_type = SELF_TYPE_LV0;
    } else if (strcmp(value, "LV1") == 0) {
      keyset->self_type = SELF_TYPE_LV1;		 
    } else if (strcmp(value, "LV2") == 0) {
      keyset->self_type = SELF_TYPE_LV2;		 
    } else if (strcmp(value, "APP") == 0) {
      keyset->self_type = SELF_TYPE_APP;		 
    } else if (strcmp(value, "ISO") == 0) {
      keyset->self_type = SELF_TYPE_ISO;		 
    } else if (strcmp(value, "LDR") == 0) {
      keyset->self_type = SELF_TYPE_LDR;		 
    } else if (strcmp(value, "UNK_7")  == 0) {
      keyset->self_type = SELF_TYPE_UNK7;		 
    } else if (strcmp(value, "NPDRM") == 0) {
      keyset->self_type = SELF_TYPE_NPDRM;
    } else {
      printf("[*] Error: unknown SELF type '%s'.\n", value);
    }  
  } else if (strcmp(name, "erk") == 0 || strcmp(name, "key") == 0) {
    keyset->erk_key = x_to_u8_buffer(value);
    keyset->erk_len = strlen(value) >> 1;
  } else if (strcmp(name, "riv") == 0) {
    keyset->riv_len = strlen(value) >> 1;
    keyset->riv_key = x_to_u8_buffer(value);
  } else if (strcmp(name, "pub") == 0) {
    keyset->pub_key = x_to_u8_buffer(value);
  } else if (strcmp(name, "priv") == 0) {
    keyset->priv_key = x_to_u8_buffer(value);
  } else if ( strcmp(name, "ctype") == 0) {
    keyset->ctype =  x_to_u64(value);
  } else {
    printf("[*] Error: Unknown keyfile property '%s'.\n", name);
  }
}

static void keyset_list_sort() {
  list_t *new_keyset_list = list_alloc();	
  while (keyset_list->count) {
    list_node_t *major_node = list_head(keyset_list);
    list_node_t *next_node = major_node;
    while (next_node) {
      keyset_t *major = (keyset_t *) list_get(major_node);
      keyset_t *next = (keyset_t *) list_get(next_node);
      int cmp = (major->version - next->version) >> 32;
      if (cmp == 0)
	cmp = -(major->revision < next->revision);
      if (cmp < 0)
	major_node = next_node;
      next_node = list_next(next_node);
    }
    list_append_head(new_keyset_list, list_get(major_node));
    list_remove(keyset_list, list_get(major_node));
  }
  list_free(keyset_list);
  keyset_list = new_keyset_list;
}

void print_keysets(FILE *out)  {
  list_node_t *keyset_node = list_head(keyset_list);
  int max_len = 0;
  int len = 0;
  while (keyset_node) {
    keyset_t *ks = list_get(keyset_node);
    len = strlen(ks->name);
    if (len > max_len)
      max_len = len;
    keyset_node = list_next(keyset_node);
  }
  fprintf(out, " Name");
  int title_padding = max_len - 4;
  if (title_padding < 0) {
    title_padding = 0;
  }
  while (title_padding) {
    fputs(" ", out);
    --title_padding;
  }
  fprintf(stdout, " Type  Revision Version SELF-Type\n");
  keyset_node = list_head(keyset_list);
  while (keyset_node) {
    char version[7];
    keyset_t *keyset = (keyset_t *) list_get(keyset_node);
    fprintf(out, " %s", keyset->name);
    int padding = max_len - strlen(keyset->name);
    while (padding) {
      fputs(" ", out);
      --padding;
    }
    int version_major = (keyset->version >> 48) & 0xFFFF;
    int version_minor = (keyset->version >> 32) & 0xFFFF;
    sprintf(version, "%02X.%02X", version_major, version_minor);
    fprintf(out, " %-5s 0x%04X   %s   ", id2name(keyset->type, sce_types, NULL), 
                                         keyset->revision, version);
    if (keyset->type == SCE_TYPE_SELF) {
      struct id2name_tbl *t = self_long_name_types;
      while (t->name != NULL) {
	if (keyset->self_type == t->id) {
	  fprintf(out, "[%s]\n", t->name);
	  break;
	}
	t++;
      }
      if (!t) {
	fprintf(out, "0x%08X\n", keyset->self_type);
      }
    } else {
      fprintf(out,"\n");
    }
    keyset_node = list_next(keyset_node);
  }
}

int load_keysets(const char *filename) {
  keyset_list = list_alloc();
  keyset_t *current_keyset = 0;
  
  if (!keyset_list)
    return 0;
  
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    list_free(keyset_list);
    keyset_list = 0;
    return 0;
  }
  
  while (!feof(fp)) {
    char line[CONFIG_MAX_LINE_SIZE];	
    read_line(line, CONFIG_MAX_LINE_SIZE, fp);
    char start = line[0];
    int len = strlen(line);
    if (len > 1 && start != '#') {
      if (len > 2 && start == '[') {
	if (current_keyset)
	  list_append(keyset_list, current_keyset);
	int i = 0;
	while (line[i] != ']') {
	  if (line[i] == '\n' || i >= len)
	    break;
	  ++i;				
	}
	line[i] = 0;
	current_keyset = (keyset_t *)malloc(sizeof(keyset_t));
	memset(current_keyset, 0, sizeof(keyset_t));
	current_keyset->name = malloc(len + 1);
	if (!current_keyset->name)
	  return 0;
	strncpy(current_keyset->name, &line[1], len);
	current_keyset->name[len] = 0;
      } else {
	if (current_keyset) {
	  int i = 0;
	  while (line[i] != '=')  {
	    if (line[i] == '\n' || i >= len)
	      break;
	    ++i;
	  }
	  line[i] = 0;
	  add_key_to_keyset(line, &line[i + 1], current_keyset);
	}
      }
    }
  }
  list_append(keyset_list, current_keyset);
  keyset_list_sort();
  
  return 1;		
}

int load_ldr_curves(const char *filename) {
  uint32_t size;
  loader_curves = (curve_t *) _read_buffer(filename, &size);
  if (!loader_curves)
    return 0;

  if (size != sizeof(curve_t) * LOADER_CURVES_NUM) {
    free(loader_curves);
    return 0;
  }
  return 1;
}

int load_vsh_curves(const char *filename) {
  uint32_t size;
  vsh_curves = (curve_vsh_t *) _read_buffer(filename, &size);
  if (!vsh_curves)
    return 0;
		
  // FIXME: 360 total size of vsh curves
  if (size != (sizeof(curve_vsh_t) * VSH_CURVES_NUM) ) {
    free(vsh_curves);
    return 0;
  }

  return 1;
}

static keyset_t *find_self_keyset(uint16_t revision, uint32_t self_type, uint64_t version) {
  list_node_t *node = list_head(keyset_list);
  if (!node)
    return NULL;

  keyset_t *keyset;
  while (node) {
    keyset = (keyset_t *) list_get(node);
    if (keyset->self_type == self_type) {
      switch(self_type) {
      case SELF_TYPE_LV1:
      case SELF_TYPE_LV2:
	if (version >= keyset->revision) 
	  break;
	return keyset;
	
      case SELF_TYPE_ISO:
	if (version > keyset->version)
	  break;
	
      case SELF_TYPE_APP:
      case SELF_TYPE_NPDRM:
	if (revision != keyset->revision)
	  break;
	return keyset;
	
      case SELF_TYPE_LV0:
      case SELF_TYPE_LDR:
	return keyset;
	
      default:
	break;
      }
    }
    node = list_next(node);
  }
  return NULL;
}

static keyset_t *find_keyset_by_type_revision(uint32_t type, uint32_t revision) {
  list_node_t *node = list_head(keyset_list);
  while (node) {
    keyset_t *keyset = (keyset_t *) list_get(node);
    if (keyset->type == type) {
      if (revision <= keyset->revision)
	return keyset;
    }
    node = list_next(node);
  }
  return NULL;
}

keyset_t *find_keyset_from_header(sce_info_t *sce_info) {
  sce_hdr_t *sce_file = sce_info->sce_header;
  keyset_t *keyset = NULL;
  switch(sce_file->type) {
  case SCE_TYPE_SELF:
    keyset = find_self_keyset(sce_file->key_revision, 
			      sce_info->info_header->self_type,
			      sce_info->info_header->version);
    break;
  case SCE_TYPE_RVK:
  case SCE_TYPE_SPP:
  case SCE_TYPE_PKG:
    keyset = find_keyset_by_type_revision(sce_file->type, 
					  sce_file->key_revision);
    break;
  }

  if (!keyset) {
    const char *name;
    name = id2name(sce_file->type, sce_types, "UNKNOWN");
    printf("[*] Error: Could not find keyset for %s.\n", name);
  }
  return keyset;
}

uint8_t *find_key_by_name(const char *name) {
  keyset_t *keyset = find_keyset_by_name(name);
  if (!keyset)
    return NULL;
  return keyset->erk_key;
}

keyset_t *find_keyset_by_name(const char *name) {
  list_node_t *node = list_head(keyset_list);
  while (node) {
    keyset_t *keyset = (keyset_t *) list_get(node);
    if (strcmp(keyset->name, name) == 0) {
      return keyset;
    }
    node = list_next(node);
  }
  printf("[*] Error: Could not find keyset '%s'.\n", name);
  return NULL;
}

static curve_t tmp_vsh_curve;

curve_t *get_vsh_curve(uint32_t type) { 
  if (type > 2) 
    return NULL;
  
  memcpy_inv(tmp_vsh_curve.p, vsh_curves[type].p, 20); 
  memcpy_inv(tmp_vsh_curve.a, vsh_curves[type].a, 20); 
  memcpy_inv(tmp_vsh_curve.b, vsh_curves[type].b, 20);		
  // N is 20 bytes instead of 21
  tmp_vsh_curve.N[0] = 0xff;
  memcpy_inv(tmp_vsh_curve.N + 1, vsh_curves[type].N, 20); 
  memcpy_inv(tmp_vsh_curve.Gx, vsh_curves[type].Gx, 20); 
  memcpy_inv(tmp_vsh_curve.Gy, vsh_curves[type].Gy, 20); 
  
  return &tmp_vsh_curve; 
} 

static uint8_t *load_idps_key() {
  char filename[MAX_PATH];
  get_data_filename(SCE_DATA_IDPS, filename);

  uint32_t size;
  uint8_t *idps = _read_buffer(filename, &size);
  if (!idps)
    return NULL;

  if (size != 16) {
    free(idps);
    return NULL;
  }

  return idps;
}

static actdat_t *load_actdat() {
  char filename[MAX_PATH];
  uint32_t size;

  get_data_filename(SCE_DATA_ACTDAT, filename);
  actdat_t *actdat = (actdat_t *) _read_buffer(filename, &size);
  if (!actdat)
    return NULL;
  
  if (size != sizeof(actdat_t)) {
    free(actdat);
    return NULL;
  }
  return actdat;
}

static rif_t *load_rif(const uint8_t *title_id) {
  uint32_t size;
  char filename[MAX_PATH];
  char tmpfilename[MAX_PATH];
  sprintf(tmpfilename, "%s/%s%s", SCE_DATA_RIFDIR, title_id, SCE_DATA_RIFEXT); 
  get_data_filename(tmpfilename, filename);
  rif_t *rif = (rif_t *) _read_buffer(filename, &size);
  if (!rif)
    return NULL;

  if (size != sizeof(rif_t)) {
    free(rif);
    return NULL;
  }

  return rif;
}

static uint8_t *load_rap(const uint8_t *content_id) {
  uint32_t size;
  char filename[MAX_PATH];
  char tmpfilename[MAX_PATH];

  sprintf(tmpfilename, "%s/%s%s", SCE_DATA_RAPDIR, content_id, SCE_DATA_RAPEXT); 
  get_data_filename(tmpfilename, filename);
  uint8_t *rap = _read_buffer(filename, &size);
  if (!rap)
    return NULL;

  if (size != 16) {
    free(rap);
    return NULL;
  }

  return rap;
}

static int rap_to_klicensee(const uint8_t *content_id, uint8_t *klicensee) {
  uint8_t *rap_key = load_rap(content_id);
  

  uint8_t *rap_initial_key = find_key_by_name("NP_rap_initial");
  uint8_t *pbox = find_key_by_name("NP_rap_pbox");
  uint8_t *e1 = find_key_by_name("NP_rap_e1");
  uint8_t *e2 = find_key_by_name("NP_rap_e2");

  if (!rap_initial_key || !pbox || !e1 || !e2)
    return 0;
        
  int round_num;
  int i;
  
  uint8_t key[16];
  aes_context aes_ctx;
  
  if (!rap_key)
    return 0;

  aes_setkey_dec(&aes_ctx, rap_initial_key, 128);
  aes_crypt_ecb(&aes_ctx, AES_DECRYPT, rap_key, key);
  
  for (round_num = 0; round_num < 5; ++round_num) {
    for (i = 0; i < 16; ++i) {
      int p = pbox[i];
      key[p] ^= e1[p];
    }
    for (i = 15; i >= 1; --i) {
      int p = pbox[i];
      int pp = pbox[i - 1];
      key[p] ^= key[pp];
    }
    int o = 0;
    for (i = 0; i < 16; ++i) {
      int p = pbox[i];
      uint8_t kc = key[p] - o;
      uint8_t ec2 = e2[p];
      if (o != 1 || kc != 0xFF) {
	o = kc < ec2 ? 1 : 0;
	key[p] = kc - ec2;
      } else if (kc == 0xFF) {
	key[p] = kc - ec2;
      } else {
	key[p] = kc;
      }
    }
  }

  memcpy(klicensee, key, sizeof(key));
  return 1;
}

int decrypt_klicensee(const uint8_t *title_id, uint8_t *klic) {
  aes_context aes_ctx;
  if (rap_to_klicensee(title_id, klic)) {
    if (verbose == 1)
      printf("[*] klicensee converted from %s.rap.\n", title_id);
    return 1;
  }

  uint8_t *idps_key = load_idps_key();
  if (!idps_key) {
    printf("[*] Error: Could not load IDPS.\n");
    return 0;
  }
    
  if ( verbose == 1 )
    printf("[*] IDPS loaded.\n");

  actdat_t *actdat = load_actdat();
  if ( !actdat ) {
    printf("[*] Error: Could not load act.dat.\n");
    return 0;
  }

  if ( verbose == 1 )
    printf("[*] act.dat loaded.\n");
  keyset_t *idps_const_keyset = find_keyset_by_name("NP_idps_const");
  uint8_t constactdat[16];
  memcpy(constactdat, idps_const_keyset->erk_key, 16);
  keyset_t *rif_keyset = find_keyset_by_name("NP_rif_key");
  if (!idps_const_keyset  || !rif_keyset)
    return 0;
  rif_t *rif = load_rif(title_id);
  if (!rif) {
    printf("[*] Error: Could not obtain klicensee for '%s'.\n", title_id);
    return 0;
  }
  aes_setkey_dec(&aes_ctx, rif_keyset->erk_key, 128);
  aes_crypt_ecb(&aes_ctx, AES_DECRYPT, rif->padding, rif->padding);
  uint32_t actdat_idx = ES32(rif->actdat_index);
  if (actdat_idx > 127) {
    printf("[*] Error: act.dat key index out of bounds.\n");
    return 0;
  }
  uint8_t actdatkey_idx[16];
  
  memcpy(actdatkey_idx, actdat->key_table + 16 * actdat_idx, 16);
  aes_setkey_enc(&aes_ctx, idps_key, 128);
  aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, constactdat, constactdat);

  aes_setkey_dec(&aes_ctx, constactdat, 128);
  aes_crypt_ecb(&aes_ctx, AES_DECRYPT, actdatkey_idx, actdatkey_idx);

  aes_setkey_dec(&aes_ctx, actdatkey_idx, 128);
  aes_crypt_ecb(&aes_ctx, AES_DECRYPT, rif->key, klic);
  free(rif);
  if ( verbose == 1 )
    printf("[*] klicensee decrypted.\n");
  return 1;
}


keyset_t *get_keyset_from_raw(keyset_raw_t *raw) {
  keyset_t *keyset = (keyset_t *)malloc(sizeof(keyset_t));
  if (!keyset) 
    return NULL;
  
  keyset->erk_key = malloc(32);
  if (keyset->erk_key)
    memcpy(keyset->erk_key, raw->erk, 32);
  keyset->erk_len = 32;
  
  keyset->riv_key = malloc(16);
  if (keyset->riv_key)
    memcpy(keyset->riv_key, raw->riv, 16);
  keyset->riv_len = 16;
  
  keyset->pub_key = malloc(40);
  if (keyset->pub_key)
    memcpy(keyset->pub_key, raw->pub, 40);
  
  keyset->priv_key = malloc(21);
  if (keyset->priv_key)
    memcpy(keyset->priv_key, raw->priv, 21);
  
  keyset->ctype = raw->curve;
  
  return keyset;
}
