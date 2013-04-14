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
 
 #include "npdrm.h"

#include "backend.h"
#include "polarssl/aes.h"
#include "polarssl/sha1.h"
#include "ec.h"
#include "aes_omac.h"
#include "keys.h"
#include "ids.h"
#include "klics.h"

static void npd_controlflag_payload_adjust_endianness(npdrm_info_t *p) {
  p->magic = ES32(p->magic);
  p->unknown0 = ES32(p->unknown0);
  p->license_type = ES32(p->license_type) ;
  p->type = ES32(p->type);
  p->unknown1 = ES64(p->unknown1);
  p->unknown2 = ES64(p->unknown2);
}

static npdrm_info_t *npdrm_adjust_endianness_control_flag(sce_info_t *sce_info) {
	list_t *control_list = sce_info->control_flag_list;
	if (!control_list) 
		return NULL;

	list_node_t *node = list_head(control_list);
	while (node) {
		control_flag_t *flag = list_get(node);
		if (flag->header.type == CONTROLFLAG_TYPE_NPDRM) {
			npd_controlflag_payload_adjust_endianness(&flag->npdrm);
			return &flag->npdrm;
		}
		node = list_next(node);
	}
	return NULL;
}

int decrypt_with_klic(sce_info_t *sce_info) {
  npdrm_info_t *npdrm_info = npdrm_adjust_endianness_control_flag(sce_info);
  if (!npdrm_info) {
    return 0;
  }

  keyset_t *np_keyset = find_keyset_by_name("NP_klic_key");
  if (!np_keyset) {
    return 0;
  }

  uint8_t klic[16];
  uint8_t iv[16];
  aes_context aes_ctx;

  if (!klicensee) {
    klicensee = find_klicensee((char *) npdrm_info->content_id);
    if (klicensee) {
      printf("[*] Found klicensee for %s\n", npdrm_info->content_id);
    }
  }

  if (klicensee) {
    memcpy(klic, klicensee, 16);
  } else if (npdrm_info->license_type == NPDRM_LICENSETYPE_FREE) {
   keyset_t *klic_free = find_keyset_by_name("NP_klic_free");
   if (!klic_free) {
     return 0;
   }
   memcpy(klic, klic_free->erk_key, 16);
  } else if (npdrm_info->license_type == NPDRM_LICENSETYPE_LOCAL) {
   if (!decrypt_klicensee(npdrm_info->content_id, klic))
     return 0;
  } else {
    return 0;
  }
  aes_setkey_dec(&aes_ctx, np_keyset->erk_key, np_keyset->erk_len * 8);
  aes_crypt_ecb(&aes_ctx, AES_DECRYPT, klic, klic);
  aes_setkey_dec(&aes_ctx, klic, 128);
  memset(iv, 0, sizeof(iv));
  aes_crypt_cbc(&aes_ctx, AES_DECRYPT, sizeof(metadata_t), iv, (uint8_t *) sce_info->metadata_aes_keys, (uint8_t *) sce_info->metadata_aes_keys);
  return 1;
}

int npdrm_encrypt(sce_info_t *sce_info) {
  aes_context aes_ctx;
  uint8_t klic[16];
	
  npdrm_info_t *payload = npdrm_adjust_endianness_control_flag(sce_info);
  if (!payload) {
	return 0;
  }
  
  keyset_t *np_klic = find_keyset_by_name("NP_klic_key");
  
  if (!np_klic) {
	return 0;
  }

  if (klicensee) {
    memcpy(klic, klicensee, 16);
  } else if (payload->license_type == 3) {
    keyset_t *np_klic_free = find_keyset_by_name("NP_klic_free");
    if (!np_klic_free) {
      return 0;
    }
    memcpy(klic, np_klic_free->erk_key, 16);
  } else if (payload->license_type == 2) {
    if (!decrypt_klicensee(payload->content_id, klic))
      return 0;
  }
	
  uint8_t iv[16];
  memset(iv, 0, 16);

  aes_setkey_dec(&aes_ctx, np_klic->erk_key, 128);
  aes_crypt_ecb(&aes_ctx, AES_DECRYPT, klic, klic);

  aes_setkey_enc(&aes_ctx, klic, 128);
  aes_crypt_cbc(&aes_ctx, AES_ENCRYPT, sizeof(metadata_t), iv,
                sce_info->output + sce_info->metadata_aes_keys_offset,
                sce_info->output + sce_info->metadata_aes_keys_offset);
  return 1;
}

int create_npd_controlflag_payload(npdrm_encrypt_info_t *npdrm_opt, npdrm_info_t *payload) {
  uint8_t klic[16];
  static uint8_t unknown_hash[16] = { "watermarktrololo" };
  
  keyset_t *np_tid = find_keyset_by_name("NP_tid");
  keyset_t *np_ci = find_keyset_by_name("NP_ci");

  if (!np_tid || !np_ci)
    return 0;
	
  if (klicensee) {
    memcpy(klic, klicensee, 16);
  } else if (npdrm_opt->license_type == NPDRM_LICENSETYPE_FREE) {
    keyset_t *klic_free = find_keyset_by_name("NP_klic_free");
    if (!klic_free )
      return 0;
    memcpy(klic, klic_free->erk_key, 16);	
  } else if (npdrm_opt->license_type == NPDRM_LICENSETYPE_LOCAL) {
    if (!decrypt_klicensee(npdrm_opt->content_id, klic))
      return 0;
  } else
    return 0;

  payload->magic = NPDRM_MAGIC; // 0x4E504400
  payload->unknown0 = 1;
  payload->license_type = npdrm_opt->license_type;
  payload->type = npdrm_opt->app_type;
  memcpy(payload->content_id, npdrm_opt->content_id, sizeof(payload->content_id));
  memcpy(payload->hash, unknown_hash, sizeof(unknown_hash));
  payload->unknown1 = 0;
  payload->unknown2 = 0;
  npd_controlflag_payload_adjust_endianness(payload);
  
  int i = 0;
  uint8_t key[16];

  uint8_t *np_ci_key = np_ci->erk_key;
  // Xor the klic key.
  while (i< 0x10) {
	key[i] = np_ci_key[i] ^ klic[i];
	++i;
  }

  int len = strlen(npdrm_opt->real_filename) + sizeof(payload->content_id);
  char *buffer = malloc(len + 1);
  memcpy(buffer, payload->content_id, sizeof(payload->content_id));
  strcpy(buffer + sizeof(payload->content_id), npdrm_opt->real_filename);
    
  aesOmac1Mode(payload->hash_iv,  (uint8_t *) buffer, len, np_tid->erk_key, 128);
  aesOmac1Mode(payload->hash_xor, (uint8_t *) payload, 0x60, key, 128);
  return 1;
}


int add_npdrm_footer_sig(const char *filename) {
  FILE *fp; 

  uint8_t s[21]; 
  uint8_t r[21]; 
  uint8_t hash[20]; 

  static char padding[] = {
	0x8b, 0x3f, 0x7a,0x48,
	0xaf, 0x45, 0xef, 0x28,
	0x3a, 0x05, 0x98, 0x10,
	0xbc, 0x3f, 0x7a, 0x48
  };
  
  keyset_t *keyset = find_keyset_by_name("NP_sig");
  
  if ( !keyset)
	return 0;
	
  fp = fopen(filename, "r+b");
  if (!fp)
    return 0;
	
  fseek(fp, 0, SEEK_END);
  size_t size = ftell (fp);
  // Error ? SCETool takes left_not_aligned as (size & 0xF)
  size_t left_not_aligned = (0x10 - (size & 0xF)) & 0x0F;
  if (left_not_aligned) {
    fwrite(padding, 1, left_not_aligned, fp);
    size += left_not_aligned;
  }
  fseek(fp, 0, SEEK_SET);
  uint8_t *buffer = malloc(size);
  if (!buffer)  {
    fclose(fp);
    return 0;
  }

  if(fread(buffer, 1, size, fp) != size)
    return 0;
    
  
  sha1(buffer, size, hash);
  
  ecdsa_set_curve(keyset->ctype | 0x40);
  ecdsa_set_pub(keyset->pub_key);
  ecdsa_set_priv(keyset->priv_key);
  ecdsa_sign(r, s, hash);
  
  fseek(fp, 0, SEEK_END); 
  fwrite(&r[1], 20, 1, fp);
  fwrite(&s[1], 20, 1, fp);
  fwrite(&hash[12], 8, 1, fp);
  
  free(buffer);
  fclose(fp);  
  return 1;
}

