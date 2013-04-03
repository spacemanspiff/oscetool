// Copyright 2007,2008,2010  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef __BN_H_
#define __BN_H_

#ifdef __cplusplus
extern "C" {
#endif

void bn_copy(uint8_t *d, uint8_t *a, uint32_t n);
int bn_compare(uint8_t *a, uint8_t *b, uint32_t n);
void bn_reduce(uint8_t *d, uint8_t *N, uint32_t n);
void bn_add(uint8_t *d, uint8_t *a, uint8_t *b, uint8_t *N, uint32_t n);
void bn_sub(uint8_t *d, uint8_t *a, uint8_t *b, uint8_t *N, uint32_t n);
void bn_to_mon(uint8_t *d, uint8_t *N, uint32_t n);
void bn_from_mon(uint8_t *d, uint8_t *N, uint32_t n);
void bn_mon_mul(uint8_t *d, uint8_t *a, uint8_t *b, uint8_t *N, uint32_t n);
void bn_mon_inv(uint8_t *d, uint8_t *a, uint8_t *N, uint32_t n);

#ifdef __cplusplus
}
#endif

#endif
