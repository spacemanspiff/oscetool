// Copyright 2007,2008,2010  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <string.h>
#include <stdio.h>

#include "types.h"
//#include "tools.h"
#include "bn.h"
#include "keys.h"
#include "mt19937.h"

struct point {
	uint8_t x[20];
	uint8_t y[20];
};

static uint8_t ec_p[20];
static uint8_t ec_a[20];	// mon
static uint8_t ec_b[20];	// mon
static uint8_t ec_N[21];
static struct point ec_G;	// mon
static struct point ec_Q;	// mon
static uint8_t ec_k[21];

static int ecdsa_get_params(uint32_t type, uint8_t *p, uint8_t *a, uint8_t *b, uint8_t *N, uint8_t *Gx, uint8_t *Gy);

static void elt_copy(uint8_t *d, uint8_t *a)
{
	memcpy(d, a, 20);
}

static void elt_zero(uint8_t *d)
{
	memset(d, 0, 20);
}

static int elt_is_zero(uint8_t *d)
{
	uint32_t i;

	for (i = 0; i < 20; i++)
		if (d[i] != 0)
			return 0;

	return 1;
}

static void elt_add(uint8_t *d, uint8_t *a, uint8_t *b)
{
	bn_add(d, a, b, ec_p, 20);
}

static void elt_sub(uint8_t *d, uint8_t *a, uint8_t *b)
{
	bn_sub(d, a, b, ec_p, 20);
}

static void elt_mul(uint8_t *d, uint8_t *a, uint8_t *b)
{
	bn_mon_mul(d, a, b, ec_p, 20);
}

static void elt_square(uint8_t *d, uint8_t *a)
{
	elt_mul(d, a, a);
}

static void elt_inv(uint8_t *d, uint8_t *a)
{
	uint8_t s[20];
	elt_copy(s, a);
	bn_mon_inv(d, s, ec_p, 20);
}

static void point_to_mon(struct point *p)
{
	bn_to_mon(p->x, ec_p, 20);
	bn_to_mon(p->y, ec_p, 20);
}

static void point_from_mon(struct point *p)
{
	bn_from_mon(p->x, ec_p, 20);
	bn_from_mon(p->y, ec_p, 20);
}

#if 0
static int point_is_on_curve(uint8_t *p)
{
	uint8_t s[20], t[20];
	uint8_t *x, *y;

	x = p;
	y = p + 20;

	elt_square(t, x);
	elt_mul(s, t, x);

	elt_mul(t, x, ec_a);
	elt_add(s, s, t);

	elt_add(s, s, ec_b);

	elt_square(t, y);
	elt_sub(s, s, t);

	return elt_is_zero(s);
}
#endif

static void point_zero(struct point *p)
{
	elt_zero(p->x);
	elt_zero(p->y);
}

static int point_is_zero(struct point *p)
{
	return elt_is_zero(p->x) && elt_is_zero(p->y);
}

static void point_double(struct point *r, struct point *p)
{
	uint8_t s[20], t[20];
	struct point pp;
	uint8_t *px, *py, *rx, *ry;

	pp = *p;

	px = pp.x;
	py = pp.y;
	rx = r->x;
	ry = r->y;

	if (elt_is_zero(py)) {
		point_zero(r);
		return;
	}

	elt_square(t, px);	// t = px*px
	elt_add(s, t, t);	// s = 2*px*px
	elt_add(s, s, t);	// s = 3*px*px
	elt_add(s, s, ec_a);	// s = 3*px*px + a
	elt_add(t, py, py);	// t = 2*py
	elt_inv(t, t);		// t = 1/(2*py)
	elt_mul(s, s, t);	// s = (3*px*px+a)/(2*py)

	elt_square(rx, s);	// rx = s*s
	elt_add(t, px, px);	// t = 2*px
	elt_sub(rx, rx, t);	// rx = s*s - 2*px

	elt_sub(t, px, rx);	// t = -(rx-px)
	elt_mul(ry, s, t);	// ry = -s*(rx-px)
	elt_sub(ry, ry, py);	// ry = -s*(rx-px) - py
}

static void point_add(struct point *r, struct point *p, struct point *q)
{
	uint8_t s[20], t[20], u[20];
	uint8_t *px, *py, *qx, *qy, *rx, *ry;
	struct point pp, qq;

	pp = *p;
	qq = *q;

	px = pp.x;
	py = pp.y;
	qx = qq.x;
	qy = qq.y;
	rx = r->x;
	ry = r->y;

	if (point_is_zero(&pp)) {
		elt_copy(rx, qx);
		elt_copy(ry, qy);
		return;
	}

	if (point_is_zero(&qq)) {
		elt_copy(rx, px);
		elt_copy(ry, py);
		return;
	}

	elt_sub(u, qx, px);

	if (elt_is_zero(u)) {
		elt_sub(u, qy, py);
		if (elt_is_zero(u))
			point_double(r, &pp);
		else
			point_zero(r);

		return;
	}

	elt_inv(t, u);		// t = 1/(qx-px)
	elt_sub(u, qy, py);	// u = qy-py
	elt_mul(s, t, u);	// s = (qy-py)/(qx-px)

	elt_square(rx, s);	// rx = s*s
	elt_add(t, px, qx);	// t = px+qx
	elt_sub(rx, rx, t);	// rx = s*s - (px+qx)

	elt_sub(t, px, rx);	// t = -(rx-px)
	elt_mul(ry, s, t);	// ry = -s*(rx-px)
	elt_sub(ry, ry, py);	// ry = -s*(rx-px) - py
}

static void point_mul(struct point *d, uint8_t *a, struct point *b)	// a is bignum
{
	uint32_t i;
	uint8_t mask;

	point_zero(d);

	for (i = 0; i < 21; i++)
		for (mask = 0x80; mask != 0; mask >>= 1) {
			point_double(d, d);
			if ((a[i] & mask) != 0)
				point_add(d, d, b);
		}
}

static void generate_ecdsa(uint8_t *R, uint8_t *S, uint8_t *k, uint8_t *hash)
{
	uint8_t e[21];
	uint8_t kk[21];
	uint8_t m[21];
	uint8_t minv[21];
	struct point mG;

	e[0] = 0;
	memcpy(e + 1, hash, 20);
	bn_reduce(e, ec_N, 21);

try_again:

	get_rand(m, sizeof m);
	m[0] = 0;
	if (bn_compare(m, ec_N, 21) >= 0)
		goto try_again;

	//	R = (mG).x

	point_mul(&mG, m, &ec_G);
	point_from_mon(&mG);
	R[0] = 0;
	elt_copy(R+1, mG.x);

	//	S = m**-1*(e + Rk) (mod N)

	bn_copy(kk, k, 21);
	bn_reduce(kk, ec_N, 21);
	bn_to_mon(m, ec_N, 21);
	bn_to_mon(e, ec_N, 21);
	bn_to_mon(R, ec_N, 21);
	bn_to_mon(kk, ec_N, 21);

	bn_mon_mul(S, R, kk, ec_N, 21);
	bn_add(kk, S, e, ec_N, 21);
	bn_mon_inv(minv, m, ec_N, 21);
	bn_mon_mul(S, minv, kk, ec_N, 21);

	bn_from_mon(R, ec_N, 21);
	bn_from_mon(S, ec_N, 21);
}

static int check_ecdsa(struct point *Q, uint8_t *R, uint8_t *S, uint8_t *hash)
{
	uint8_t Sinv[21];
	uint8_t e[21];
	uint8_t w1[21], w2[21];
	struct point r1, r2;
	uint8_t rr[21];

	e[0] = 0;
	memcpy(e + 1, hash, 20);
	bn_reduce(e, ec_N, 21);

	bn_to_mon(R, ec_N, 21);
	bn_to_mon(S, ec_N, 21);
	bn_to_mon(e, ec_N, 21);

	bn_mon_inv(Sinv, S, ec_N, 21);

	bn_mon_mul(w1, e, Sinv, ec_N, 21);
	bn_mon_mul(w2, R, Sinv, ec_N, 21);

	bn_from_mon(w1, ec_N, 21);
	bn_from_mon(w2, ec_N, 21);

	point_mul(&r1, w1, &ec_G);
	point_mul(&r2, w2, Q);

	point_add(&r1, &r1, &r2);

	point_from_mon(&r1);

	rr[0] = 0;
	memcpy(rr + 1, r1.x, 20);
	bn_reduce(rr, ec_N, 21);

	bn_from_mon(R, ec_N, 21);
	bn_from_mon(S, ec_N, 21);

	return (bn_compare(rr, R, 21) == 0);
}

#if 0
static void ec_priv_to_pub(uint8_t *k, uint8_t *Q)
{
	point_mul(Q, k, ec_G);
}
#endif

int ecdsa_set_curve(uint32_t type)
{
	if (ecdsa_get_params(type, ec_p, ec_a, ec_b, ec_N, ec_G.x, ec_G.y) < 0)
		return -1;

	bn_to_mon(ec_a, ec_p, 20);
	bn_to_mon(ec_b, ec_p, 20);

	point_to_mon(&ec_G);

	return 0;
}

void ecdsa_set_pub(uint8_t *Q)
{
	memcpy(ec_Q.x, Q, 20);
	memcpy(ec_Q.y, Q+20, 20);
	point_to_mon(&ec_Q);
}

void ecdsa_set_priv(uint8_t *k)
{
	memcpy(ec_k, k, sizeof ec_k);
}

int ecdsa_verify(uint8_t *hash, uint8_t *R, uint8_t *S)
{
	return check_ecdsa(&ec_Q, R, S, hash);
}

void ecdsa_sign(uint8_t *hash, uint8_t *R, uint8_t *S)
{
	generate_ecdsa(R, S, ec_k, hash);
}

static int ecdsa_get_params(uint32_t type, uint8_t *p, uint8_t *a, uint8_t *b, uint8_t *N, uint8_t *Gx, uint8_t *Gy) { 
	curve_t *curve = NULL;
	if (type & 0x40) {
		curve = get_vsh_curve(type & 0xBF);
		if (!curve)
			return 0;
	} else {
		curve = &loader_curves[type];
	}
  
        memcpy_inv(p, curve->p, 20); 
        memcpy_inv(a, curve->a, 20); 
        memcpy_inv(b, curve->b, 20);		
	memcpy_inv(N, curve->N, 21); 
        memcpy_inv(Gx, curve->Gx, 20); 
        memcpy_inv(Gy, curve->Gy, 20); 
 
        return 1; 
} 
