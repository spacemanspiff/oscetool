// Copyright 2007,2008,2010  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef __EC_H_
#define __EC_H_

#ifdef __cplusplus
extern "C" {
#endif

int ecdsa_get_params(uint32_t type, uint8_t *p, uint8_t *a, uint8_t *b, uint8_t *N, uint8_t *Gx, uint8_t *Gy);
int ecdsa_set_curve(uint32_t type);
void ecdsa_set_pub(uint8_t *Q);
void ecdsa_set_priv(uint8_t *k);
int ecdsa_verify(uint8_t *hash, uint8_t *R, uint8_t *S);
void ecdsa_sign(uint8_t *hash, uint8_t *R, uint8_t *S);

#ifdef __cplusplus
}
#endif

#endif
