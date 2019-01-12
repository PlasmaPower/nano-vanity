// Cobbled together from the ed25519 reference implementation.

typedef short uint16_t;
typedef int int32_t;

#define mul32x32_64(a,b) (((uint64_t)(a))*(b))
#define DONNA_NOINLINE __attribute__((noinline))
#define ALIGN(x) __attribute__((aligned(x)))
#define ROTL32(a,b) (((a) << (b)) | ((a) >> (32 - b)))

typedef unsigned char curved25519_key[32];

#define bignum256modm_bits_per_limb 30
#define bignum256modm_limb_size 9

typedef uint32_t bignum256modm_element_t;
typedef bignum256modm_element_t bignum256modm[9];

#define U8TO32_LE(p) ( \
	((uint32_t)(((uchar*) (p))[0])      ) | \
	((uint32_t)(((uchar*) (p))[1]) <<  8) | \
	((uint32_t)(((uchar*) (p))[2]) << 16) | \
	((uint32_t)(((uchar*) (p))[3]) << 24) \
)

static inline void U32TO8_LE(unsigned char *p, const uint32_t v) {
	p[0] = (unsigned char)(v      );
	p[1] = (unsigned char)(v >>  8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}

__constant bignum256modm modm_m = {
	0x1cf5d3ed, 0x20498c69, 0x2f79cd65, 0x37be77a8,
	0x00000014,	0x00000000, 0x00000000,	0x00000000,
	0x00001000
};

__constant bignum256modm modm_mu = {
	0x0a2c131b, 0x3673968c, 0x06329a7e, 0x01885742,
	0x3fffeb21, 0x3fffffff, 0x3fffffff, 0x3fffffff,
	0x000fffff
};

static bignum256modm_element_t
lt_modm(bignum256modm_element_t a, bignum256modm_element_t b) {
	return (a - b) >> 31;
}

/* see HAC, Alg. 14.42 Step 4 */
static void
reduce256_modm(bignum256modm r) {
	bignum256modm t;
	bignum256modm_element_t b = 0, pb, mask;

	/* t = r - m */
	pb = 0;
	pb += modm_m[0]; b = lt_modm(r[0], pb); t[0] = (r[0] - pb + (b << 30)); pb = b;
	pb += modm_m[1]; b = lt_modm(r[1], pb); t[1] = (r[1] - pb + (b << 30)); pb = b;
	pb += modm_m[2]; b = lt_modm(r[2], pb); t[2] = (r[2] - pb + (b << 30)); pb = b;
	pb += modm_m[3]; b = lt_modm(r[3], pb); t[3] = (r[3] - pb + (b << 30)); pb = b;
	pb += modm_m[4]; b = lt_modm(r[4], pb); t[4] = (r[4] - pb + (b << 30)); pb = b;
	pb += modm_m[5]; b = lt_modm(r[5], pb); t[5] = (r[5] - pb + (b << 30)); pb = b;
	pb += modm_m[6]; b = lt_modm(r[6], pb); t[6] = (r[6] - pb + (b << 30)); pb = b;
	pb += modm_m[7]; b = lt_modm(r[7], pb); t[7] = (r[7] - pb + (b << 30)); pb = b;
	pb += modm_m[8]; b = lt_modm(r[8], pb); t[8] = (r[8] - pb + (b << 16));

	/* keep r if r was smaller than m */
	mask = b - 1;
	r[0] ^= mask & (r[0] ^ t[0]);
	r[1] ^= mask & (r[1] ^ t[1]);
	r[2] ^= mask & (r[2] ^ t[2]);
	r[3] ^= mask & (r[3] ^ t[3]);
	r[4] ^= mask & (r[4] ^ t[4]);
	r[5] ^= mask & (r[5] ^ t[5]);
	r[6] ^= mask & (r[6] ^ t[6]);
	r[7] ^= mask & (r[7] ^ t[7]);
	r[8] ^= mask & (r[8] ^ t[8]);
}

/*
	Barrett reduction,  see HAC, Alg. 14.42

	Instead of passing in x, pre-process in to q1 and r1 for efficiency
*/
static void
barrett_reduce256_modm(bignum256modm r, const bignum256modm q1, const bignum256modm r1) {
	bignum256modm q3, r2;
	uint64_t c;
	bignum256modm_element_t f, b, pb;

	/* q1 = x >> 248 = 264 bits = 9 30 bit elements
	   q2 = mu * q1
	   q3 = (q2 / 256(32+1)) = q2 / (2^8)^(32+1) = q2 >> 264 */
	c  = mul32x32_64(modm_mu[0], q1[7]) + mul32x32_64(modm_mu[1], q1[6]) + mul32x32_64(modm_mu[2], q1[5]) + mul32x32_64(modm_mu[3], q1[4]) + mul32x32_64(modm_mu[4], q1[3]) + mul32x32_64(modm_mu[5], q1[2]) + mul32x32_64(modm_mu[6], q1[1]) + mul32x32_64(modm_mu[7], q1[0]); 
	c >>= 30;
	c += mul32x32_64(modm_mu[0], q1[8]) + mul32x32_64(modm_mu[1], q1[7]) + mul32x32_64(modm_mu[2], q1[6]) + mul32x32_64(modm_mu[3], q1[5]) + mul32x32_64(modm_mu[4], q1[4]) + mul32x32_64(modm_mu[5], q1[3]) + mul32x32_64(modm_mu[6], q1[2]) + mul32x32_64(modm_mu[7], q1[1]) + mul32x32_64(modm_mu[8], q1[0]);
	f = (bignum256modm_element_t)c; q3[0] = (f >> 24) & 0x3f; c >>= 30;
	c += mul32x32_64(modm_mu[1], q1[8]) + mul32x32_64(modm_mu[2], q1[7]) + mul32x32_64(modm_mu[3], q1[6]) + mul32x32_64(modm_mu[4], q1[5]) + mul32x32_64(modm_mu[5], q1[4]) + mul32x32_64(modm_mu[6], q1[3]) + mul32x32_64(modm_mu[7], q1[2]) + mul32x32_64(modm_mu[8], q1[1]);
	f = (bignum256modm_element_t)c; q3[0] |= (f << 6) & 0x3fffffff; q3[1] = (f >> 24) & 0x3f; c >>= 30;
	c += mul32x32_64(modm_mu[2], q1[8]) + mul32x32_64(modm_mu[3], q1[7]) + mul32x32_64(modm_mu[4], q1[6]) + mul32x32_64(modm_mu[5], q1[5]) + mul32x32_64(modm_mu[6], q1[4]) + mul32x32_64(modm_mu[7], q1[3]) + mul32x32_64(modm_mu[8], q1[2]);
	f = (bignum256modm_element_t)c; q3[1] |= (f << 6) & 0x3fffffff; q3[2] = (f >> 24) & 0x3f; c >>= 30;
	c += mul32x32_64(modm_mu[3], q1[8]) + mul32x32_64(modm_mu[4], q1[7]) + mul32x32_64(modm_mu[5], q1[6]) + mul32x32_64(modm_mu[6], q1[5]) + mul32x32_64(modm_mu[7], q1[4]) + mul32x32_64(modm_mu[8], q1[3]);
	f = (bignum256modm_element_t)c; q3[2] |= (f << 6) & 0x3fffffff; q3[3] = (f >> 24) & 0x3f; c >>= 30;
	c += mul32x32_64(modm_mu[4], q1[8]) + mul32x32_64(modm_mu[5], q1[7]) + mul32x32_64(modm_mu[6], q1[6]) + mul32x32_64(modm_mu[7], q1[5]) + mul32x32_64(modm_mu[8], q1[4]);
	f = (bignum256modm_element_t)c; q3[3] |= (f << 6) & 0x3fffffff; q3[4] = (f >> 24) & 0x3f; c >>= 30;
	c += mul32x32_64(modm_mu[5], q1[8]) + mul32x32_64(modm_mu[6], q1[7]) + mul32x32_64(modm_mu[7], q1[6]) + mul32x32_64(modm_mu[8], q1[5]);
	f = (bignum256modm_element_t)c; q3[4] |= (f << 6) & 0x3fffffff; q3[5] = (f >> 24) & 0x3f; c >>= 30;
	c += mul32x32_64(modm_mu[6], q1[8]) + mul32x32_64(modm_mu[7], q1[7]) + mul32x32_64(modm_mu[8], q1[6]);
	f = (bignum256modm_element_t)c; q3[5] |= (f << 6) & 0x3fffffff; q3[6] = (f >> 24) & 0x3f; c >>= 30;
	c += mul32x32_64(modm_mu[7], q1[8]) + mul32x32_64(modm_mu[8], q1[7]);
	f = (bignum256modm_element_t)c; q3[6] |= (f << 6) & 0x3fffffff; q3[7] = (f >> 24) & 0x3f; c >>= 30;
	c += mul32x32_64(modm_mu[8], q1[8]);
	f = (bignum256modm_element_t)c; q3[7] |= (f << 6) & 0x3fffffff; q3[8] = (bignum256modm_element_t)(c >> 24);

	/* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1)
	   r2 = (q3 * m) mod (256^(32+1)) = (q3 * m) & ((1 << 264) - 1) */
	c = mul32x32_64(modm_m[0], q3[0]);
	r2[0] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
	c += mul32x32_64(modm_m[0], q3[1]) + mul32x32_64(modm_m[1], q3[0]);
	r2[1] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
	c += mul32x32_64(modm_m[0], q3[2]) + mul32x32_64(modm_m[1], q3[1]) + mul32x32_64(modm_m[2], q3[0]);
	r2[2] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
	c += mul32x32_64(modm_m[0], q3[3]) + mul32x32_64(modm_m[1], q3[2]) + mul32x32_64(modm_m[2], q3[1]) + mul32x32_64(modm_m[3], q3[0]);
	r2[3] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
	c += mul32x32_64(modm_m[0], q3[4]) + mul32x32_64(modm_m[1], q3[3]) + mul32x32_64(modm_m[2], q3[2]) + mul32x32_64(modm_m[3], q3[1]) + mul32x32_64(modm_m[4], q3[0]);
	r2[4] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
	c += mul32x32_64(modm_m[0], q3[5]) + mul32x32_64(modm_m[1], q3[4]) + mul32x32_64(modm_m[2], q3[3]) + mul32x32_64(modm_m[3], q3[2]) + mul32x32_64(modm_m[4], q3[1]) + mul32x32_64(modm_m[5], q3[0]);
	r2[5] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
	c += mul32x32_64(modm_m[0], q3[6]) + mul32x32_64(modm_m[1], q3[5]) + mul32x32_64(modm_m[2], q3[4]) + mul32x32_64(modm_m[3], q3[3]) + mul32x32_64(modm_m[4], q3[2]) + mul32x32_64(modm_m[5], q3[1]) + mul32x32_64(modm_m[6], q3[0]);
	r2[6] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
	c += mul32x32_64(modm_m[0], q3[7]) + mul32x32_64(modm_m[1], q3[6]) + mul32x32_64(modm_m[2], q3[5]) + mul32x32_64(modm_m[3], q3[4]) + mul32x32_64(modm_m[4], q3[3]) + mul32x32_64(modm_m[5], q3[2]) + mul32x32_64(modm_m[6], q3[1]) + mul32x32_64(modm_m[7], q3[0]);
	r2[7] = (bignum256modm_element_t)(c & 0x3fffffff); c >>= 30;
	c += mul32x32_64(modm_m[0], q3[8]) + mul32x32_64(modm_m[1], q3[7]) + mul32x32_64(modm_m[2], q3[6]) + mul32x32_64(modm_m[3], q3[5]) + mul32x32_64(modm_m[4], q3[4]) + mul32x32_64(modm_m[5], q3[3]) + mul32x32_64(modm_m[6], q3[2]) + mul32x32_64(modm_m[7], q3[1]) + mul32x32_64(modm_m[8], q3[0]);
	r2[8] = (bignum256modm_element_t)(c & 0xffffff);

	/* r = r1 - r2
	   if (r < 0) r += (1 << 264) */
	pb = 0;
	pb += r2[0]; b = lt_modm(r1[0], pb); r[0] = (r1[0] - pb + (b << 30)); pb = b;
	pb += r2[1]; b = lt_modm(r1[1], pb); r[1] = (r1[1] - pb + (b << 30)); pb = b;
	pb += r2[2]; b = lt_modm(r1[2], pb); r[2] = (r1[2] - pb + (b << 30)); pb = b;
	pb += r2[3]; b = lt_modm(r1[3], pb); r[3] = (r1[3] - pb + (b << 30)); pb = b;
	pb += r2[4]; b = lt_modm(r1[4], pb); r[4] = (r1[4] - pb + (b << 30)); pb = b;
	pb += r2[5]; b = lt_modm(r1[5], pb); r[5] = (r1[5] - pb + (b << 30)); pb = b;
	pb += r2[6]; b = lt_modm(r1[6], pb); r[6] = (r1[6] - pb + (b << 30)); pb = b;
	pb += r2[7]; b = lt_modm(r1[7], pb); r[7] = (r1[7] - pb + (b << 30)); pb = b;
	pb += r2[8]; b = lt_modm(r1[8], pb); r[8] = (r1[8] - pb + (b << 24));

	reduce256_modm(r);
	reduce256_modm(r);
}

/* addition modulo m */
static void
add256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y) {
	bignum256modm_element_t c;

	c  = x[0] + y[0]; r[0] = c & 0x3fffffff; c >>= 30;
	c += x[1] + y[1]; r[1] = c & 0x3fffffff; c >>= 30;
	c += x[2] + y[2]; r[2] = c & 0x3fffffff; c >>= 30;
	c += x[3] + y[3]; r[3] = c & 0x3fffffff; c >>= 30;
	c += x[4] + y[4]; r[4] = c & 0x3fffffff; c >>= 30;
	c += x[5] + y[5]; r[5] = c & 0x3fffffff; c >>= 30;
	c += x[6] + y[6]; r[6] = c & 0x3fffffff; c >>= 30;
	c += x[7] + y[7]; r[7] = c & 0x3fffffff; c >>= 30;
	c += x[8] + y[8]; r[8] = c;

	reduce256_modm(r);
}

/* multiplication modulo m */
static void 
mul256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y) {
	bignum256modm r1, q1;
	uint64_t c;
	bignum256modm_element_t f;

	/* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1)
	   q1 = x >> 248 = 264 bits = 9 30 bit elements */
	c = mul32x32_64(x[0], y[0]);
	f = (bignum256modm_element_t)c; r1[0] = (f & 0x3fffffff); c >>= 30;
	c += mul32x32_64(x[0], y[1]) + mul32x32_64(x[1], y[0]);
	f = (bignum256modm_element_t)c; r1[1] = (f & 0x3fffffff); c >>= 30;
	c += mul32x32_64(x[0], y[2]) + mul32x32_64(x[1], y[1]) + mul32x32_64(x[2], y[0]);
	f = (bignum256modm_element_t)c; r1[2] = (f & 0x3fffffff); c >>= 30;
	c += mul32x32_64(x[0], y[3]) + mul32x32_64(x[1], y[2]) + mul32x32_64(x[2], y[1]) + mul32x32_64(x[3], y[0]);
	f = (bignum256modm_element_t)c; r1[3] = (f & 0x3fffffff); c >>= 30;
	c += mul32x32_64(x[0], y[4]) + mul32x32_64(x[1], y[3]) + mul32x32_64(x[2], y[2]) + mul32x32_64(x[3], y[1]) + mul32x32_64(x[4], y[0]);
	f = (bignum256modm_element_t)c; r1[4] = (f & 0x3fffffff); c >>= 30;
	c += mul32x32_64(x[0], y[5]) + mul32x32_64(x[1], y[4]) + mul32x32_64(x[2], y[3]) + mul32x32_64(x[3], y[2]) + mul32x32_64(x[4], y[1]) + mul32x32_64(x[5], y[0]);
	f = (bignum256modm_element_t)c; r1[5] = (f & 0x3fffffff); c >>= 30;
	c += mul32x32_64(x[0], y[6]) + mul32x32_64(x[1], y[5]) + mul32x32_64(x[2], y[4]) + mul32x32_64(x[3], y[3]) + mul32x32_64(x[4], y[2]) + mul32x32_64(x[5], y[1]) + mul32x32_64(x[6], y[0]);
	f = (bignum256modm_element_t)c; r1[6] = (f & 0x3fffffff); c >>= 30;
	c += mul32x32_64(x[0], y[7]) + mul32x32_64(x[1], y[6]) + mul32x32_64(x[2], y[5]) + mul32x32_64(x[3], y[4]) + mul32x32_64(x[4], y[3]) + mul32x32_64(x[5], y[2]) + mul32x32_64(x[6], y[1]) + mul32x32_64(x[7], y[0]);
	f = (bignum256modm_element_t)c; r1[7] = (f & 0x3fffffff); c >>= 30;
	c += mul32x32_64(x[0], y[8]) + mul32x32_64(x[1], y[7]) + mul32x32_64(x[2], y[6]) + mul32x32_64(x[3], y[5]) + mul32x32_64(x[4], y[4]) + mul32x32_64(x[5], y[3]) + mul32x32_64(x[6], y[2]) + mul32x32_64(x[7], y[1]) + mul32x32_64(x[8], y[0]);
	f = (bignum256modm_element_t)c; r1[8] = (f & 0x00ffffff); q1[0] = (f >> 8) & 0x3fffff; c >>= 30;
	c += mul32x32_64(x[1], y[8]) + mul32x32_64(x[2], y[7]) + mul32x32_64(x[3], y[6]) + mul32x32_64(x[4], y[5]) + mul32x32_64(x[5], y[4]) + mul32x32_64(x[6], y[3]) + mul32x32_64(x[7], y[2]) + mul32x32_64(x[8], y[1]);
	f = (bignum256modm_element_t)c; q1[0] = (q1[0] | (f << 22)) & 0x3fffffff; q1[1] = (f >> 8) & 0x3fffff; c >>= 30;	
	c += mul32x32_64(x[2], y[8]) + mul32x32_64(x[3], y[7]) + mul32x32_64(x[4], y[6]) + mul32x32_64(x[5], y[5]) + mul32x32_64(x[6], y[4]) + mul32x32_64(x[7], y[3]) + mul32x32_64(x[8], y[2]);
	f = (bignum256modm_element_t)c; q1[1] = (q1[1] | (f << 22)) & 0x3fffffff; q1[2] = (f >> 8) & 0x3fffff; c >>= 30;	
	c += mul32x32_64(x[3], y[8]) + mul32x32_64(x[4], y[7]) + mul32x32_64(x[5], y[6]) + mul32x32_64(x[6], y[5]) + mul32x32_64(x[7], y[4]) + mul32x32_64(x[8], y[3]);
	f = (bignum256modm_element_t)c; q1[2] = (q1[2] | (f << 22)) & 0x3fffffff; q1[3] = (f >> 8) & 0x3fffff; c >>= 30;	
	c += mul32x32_64(x[4], y[8]) + mul32x32_64(x[5], y[7]) + mul32x32_64(x[6], y[6]) + mul32x32_64(x[7], y[5]) + mul32x32_64(x[8], y[4]);
	f = (bignum256modm_element_t)c; q1[3] = (q1[3] | (f << 22)) & 0x3fffffff; q1[4] = (f >> 8) & 0x3fffff; c >>= 30;	
	c += mul32x32_64(x[5], y[8]) + mul32x32_64(x[6], y[7]) + mul32x32_64(x[7], y[6]) + mul32x32_64(x[8], y[5]);
	f = (bignum256modm_element_t)c; q1[4] = (q1[4] | (f << 22)) & 0x3fffffff; q1[5] = (f >> 8) & 0x3fffff; c >>= 30;
	c += mul32x32_64(x[6], y[8]) + mul32x32_64(x[7], y[7]) + mul32x32_64(x[8], y[6]);
	f = (bignum256modm_element_t)c; q1[5] = (q1[5] | (f << 22)) & 0x3fffffff; q1[6] = (f >> 8) & 0x3fffff; c >>= 30;
	c += mul32x32_64(x[7], y[8]) + mul32x32_64(x[8], y[7]);
	f = (bignum256modm_element_t)c; q1[6] = (q1[6] | (f << 22)) & 0x3fffffff; q1[7] = (f >> 8) & 0x3fffff; c >>= 30;
	c += mul32x32_64(x[8], y[8]);
	f = (bignum256modm_element_t)c; q1[7] = (q1[7] | (f << 22)) & 0x3fffffff; q1[8] = (f >> 8) & 0x3fffff;

	barrett_reduce256_modm(r, q1, r1);
}

static void
expand256_modm(bignum256modm out, const unsigned char *in, size_t len) {
	unsigned char work[64];
	bignum256modm_element_t x[16];
	bignum256modm q1;

	for (size_t i = 0; i < len; i++) work[i] = in[i];
	for (size_t i = len; i < 64; i++) work[i] = 0;
	x[0] = U8TO32_LE(work +  0);
	x[1] = U8TO32_LE(work +  4);
	x[2] = U8TO32_LE(work +  8);
	x[3] = U8TO32_LE(work + 12);
	x[4] = U8TO32_LE(work + 16);
	x[5] = U8TO32_LE(work + 20);
	x[6] = U8TO32_LE(work + 24);
	x[7] = U8TO32_LE(work + 28);
	x[8] = U8TO32_LE(work + 32);
	x[9] = U8TO32_LE(work + 36);
	x[10] = U8TO32_LE(work + 40);
	x[11] = U8TO32_LE(work + 44);
	x[12] = U8TO32_LE(work + 48);
	x[13] = U8TO32_LE(work + 52);
	x[14] = U8TO32_LE(work + 56);
	x[15] = U8TO32_LE(work + 60);

	/* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1) */
	out[0] = (                         x[0]) & 0x3fffffff;
	out[1] = ((x[ 0] >> 30) | (x[ 1] <<  2)) & 0x3fffffff;
	out[2] = ((x[ 1] >> 28) | (x[ 2] <<  4)) & 0x3fffffff;
	out[3] = ((x[ 2] >> 26) | (x[ 3] <<  6)) & 0x3fffffff;
	out[4] = ((x[ 3] >> 24) | (x[ 4] <<  8)) & 0x3fffffff;
	out[5] = ((x[ 4] >> 22) | (x[ 5] << 10)) & 0x3fffffff;
	out[6] = ((x[ 5] >> 20) | (x[ 6] << 12)) & 0x3fffffff;
	out[7] = ((x[ 6] >> 18) | (x[ 7] << 14)) & 0x3fffffff;
	out[8] = ((x[ 7] >> 16) | (x[ 8] << 16)) & 0x00ffffff;

	/* 8*31 = 248 bits, no need to reduce */
	if (len < 32)
		return;

	/* q1 = x >> 248 = 264 bits = 9 30 bit elements */
	q1[0] = ((x[ 7] >> 24) | (x[ 8] <<  8)) & 0x3fffffff;
	q1[1] = ((x[ 8] >> 22) | (x[ 9] << 10)) & 0x3fffffff;
	q1[2] = ((x[ 9] >> 20) | (x[10] << 12)) & 0x3fffffff;
	q1[3] = ((x[10] >> 18) | (x[11] << 14)) & 0x3fffffff;
	q1[4] = ((x[11] >> 16) | (x[12] << 16)) & 0x3fffffff;
	q1[5] = ((x[12] >> 14) | (x[13] << 18)) & 0x3fffffff;
	q1[6] = ((x[13] >> 12) | (x[14] << 20)) & 0x3fffffff;
	q1[7] = ((x[14] >> 10) | (x[15] << 22)) & 0x3fffffff;
	q1[8] = ((x[15] >>  8)                );	

	barrett_reduce256_modm(out, q1, out);
}

static void
expand_raw256_modm(bignum256modm out, const unsigned char in[32]) {
	bignum256modm_element_t x[8];

	x[0] = U8TO32_LE(in +  0);
	x[1] = U8TO32_LE(in +  4);
	x[2] = U8TO32_LE(in +  8);
	x[3] = U8TO32_LE(in + 12);
	x[4] = U8TO32_LE(in + 16);
	x[5] = U8TO32_LE(in + 20);
	x[6] = U8TO32_LE(in + 24);
	x[7] = U8TO32_LE(in + 28);

	out[0] = (                         x[0]) & 0x3fffffff;
	out[1] = ((x[ 0] >> 30) | (x[ 1] <<  2)) & 0x3fffffff;
	out[2] = ((x[ 1] >> 28) | (x[ 2] <<  4)) & 0x3fffffff;
	out[3] = ((x[ 2] >> 26) | (x[ 3] <<  6)) & 0x3fffffff;
	out[4] = ((x[ 3] >> 24) | (x[ 4] <<  8)) & 0x3fffffff;
	out[5] = ((x[ 4] >> 22) | (x[ 5] << 10)) & 0x3fffffff;
	out[6] = ((x[ 5] >> 20) | (x[ 6] << 12)) & 0x3fffffff;
	out[7] = ((x[ 6] >> 18) | (x[ 7] << 14)) & 0x3fffffff;
	out[8] = ((x[ 7] >> 16)                ) & 0x0000ffff;
}

static void
contract256_window4_modm(signed char r[64], const bignum256modm in) {
	char carry;
	signed char *quads = (__private signed char *) r;
	bignum256modm_element_t i, j, v;

	for (i = 0; i < 8; i += 2) {
		v = in[i];
		for (j = 0; j < 7; j++) {
			*quads++ = (v & 15);
			v >>= 4;
		}
		v |= (in[i+1] << 2);
		for (j = 0; j < 8; j++) {
			*quads++ = (v & 15);
			v >>= 4;
		}
	}
	v = in[8];
	*quads++ = (v & 15); v >>= 4;
	*quads++ = (v & 15); v >>= 4;
	*quads++ = (v & 15); v >>= 4;
	*quads++ = (v & 15); v >>= 4;

	/* making it signed */
	carry = 0;
	for(i = 0; i < 63; i++) {
		r[i] += carry;
		r[i+1] += (r[i] >> 4);
		r[i] &= 15;
		carry = (r[i] >> 3);
		r[i] -= (carry << 4);
	}
	r[63] += carry;
}

static void
contract256_slidingwindow_modm(signed char r[256], const bignum256modm s, int windowsize) {
	int i,j,k,b;
	int m = (1 << (windowsize - 1)) - 1, soplen = 256;
	bignum256modm_element_t v;

	/* first put the binary expansion into r  */
	for (i = 0; i < 8; i++) {
		v = s[i];
		for (j = 0; j < 30; j++, v >>= 1)
			*r++ = (v & 1);
	}
	v = s[8];
	for (j = 0; j < 16; j++, v >>= 1)
		*r++ = (v & 1);

	/* Making it sliding window */
	for (j = 0; j < soplen; j++) {
		if (!r[j])
			continue;

		for (b = 1; (b < (soplen - j)) && (b <= 6); b++) {
			if ((r[j] + (r[j + b] << b)) <= m) {
				r[j] += r[j + b] << b;
				r[j + b] = 0;
			} else if ((r[j] - (r[j + b] << b)) >= -m) {
				r[j] -= r[j + b] << b;
				for (k = j + b; k < soplen; k++) {
					if (!r[k]) {
						r[k] = 1;
						break;
					}
					r[k] = 0;
				}
			} else if (r[j + b]) {
				break;
			}
		}
	}
}


/*
	helpers for batch verifcation, are allowed to be vartime
*/

/* out = a - b, a must be larger than b */
static void
sub256_modm_batch(bignum256modm out, const bignum256modm a, const bignum256modm b, size_t limbsize) {
	size_t i = 0;
	bignum256modm_element_t carry = 0;
	switch (limbsize) {
		case 8: out[i] = (a[i] - b[i]) - carry; carry = (out[i] >> 31); out[i] &= 0x3fffffff; i++;
		case 7: out[i] = (a[i] - b[i]) - carry; carry = (out[i] >> 31); out[i] &= 0x3fffffff; i++;
		case 6: out[i] = (a[i] - b[i]) - carry; carry = (out[i] >> 31); out[i] &= 0x3fffffff; i++;
		case 5: out[i] = (a[i] - b[i]) - carry; carry = (out[i] >> 31); out[i] &= 0x3fffffff; i++;
		case 4: out[i] = (a[i] - b[i]) - carry; carry = (out[i] >> 31); out[i] &= 0x3fffffff; i++;
		case 3: out[i] = (a[i] - b[i]) - carry; carry = (out[i] >> 31); out[i] &= 0x3fffffff; i++;
		case 2: out[i] = (a[i] - b[i]) - carry; carry = (out[i] >> 31); out[i] &= 0x3fffffff; i++;
		case 1: out[i] = (a[i] - b[i]) - carry; carry = (out[i] >> 31); out[i] &= 0x3fffffff; i++;
		case 0: 
		default: out[i] = (a[i] - b[i]) - carry;
	}
}


/* is a < b */
static int
lt256_modm_batch(const bignum256modm a, const bignum256modm b, size_t limbsize) {
	switch (limbsize) {
		case 8: if (a[8] > b[8]) return 0; if (a[8] < b[8]) return 1;
		case 7: if (a[7] > b[7]) return 0; if (a[7] < b[7]) return 1;
		case 6: if (a[6] > b[6]) return 0; if (a[6] < b[6]) return 1;
		case 5: if (a[5] > b[5]) return 0; if (a[5] < b[5]) return 1;
		case 4: if (a[4] > b[4]) return 0; if (a[4] < b[4]) return 1;
		case 3: if (a[3] > b[3]) return 0; if (a[3] < b[3]) return 1;
		case 2: if (a[2] > b[2]) return 0; if (a[2] < b[2]) return 1;
		case 1: if (a[1] > b[1]) return 0; if (a[1] < b[1]) return 1;
		case 0: if (a[0] > b[0]) return 0; if (a[0] < b[0]) return 1;
	}
	return 0;
}

/* is a <= b */
static int
lte256_modm_batch(const bignum256modm a, const bignum256modm b, size_t limbsize) {
	switch (limbsize) {
		case 8: if (a[8] > b[8]) return 0; if (a[8] < b[8]) return 1;
		case 7: if (a[7] > b[7]) return 0; if (a[7] < b[7]) return 1;
		case 6: if (a[6] > b[6]) return 0; if (a[6] < b[6]) return 1;
		case 5: if (a[5] > b[5]) return 0; if (a[5] < b[5]) return 1;
		case 4: if (a[4] > b[4]) return 0; if (a[4] < b[4]) return 1;
		case 3: if (a[3] > b[3]) return 0; if (a[3] < b[3]) return 1;
		case 2: if (a[2] > b[2]) return 0; if (a[2] < b[2]) return 1;
		case 1: if (a[1] > b[1]) return 0; if (a[1] < b[1]) return 1;
		case 0: if (a[0] > b[0]) return 0; if (a[0] < b[0]) return 1;
	}
	return 1;
}


/* is a == 0 */
static int
iszero256_modm_batch(const bignum256modm a) {
	size_t i;
	for (i = 0; i < 9; i++)
		if (a[i])
			return 0;
	return 1;
}

/* is a == 1 */
static int
isone256_modm_batch(const bignum256modm a) {
	size_t i;
	if (a[0] != 1)
		return 0;
	for (i = 1; i < 9; i++)
		if (a[i])
			return 0;
	return 1;
}

/* can a fit in to (at most) 128 bits */
static int
isatmost128bits256_modm_batch(const bignum256modm a) {
	uint32_t mask =
		((a[8]             )  | /*  16 */
		 (a[7]             )  | /*  46 */
		 (a[6]             )  | /*  76 */
		 (a[5]             )  | /* 106 */
		 (a[4] & 0x3fffff00));  /* 128 */

	return (mask == 0);
}

__constant uint32_t reduce_mask_25 = (1 << 25) - 1;
__constant uint32_t reduce_mask_26 = (1 << 26) - 1;


/* out = in */
__inline void
curve25519_copy(bignum25519 out, const bignum25519 in) {
	out[0] = in[0];
	out[1] = in[1];
	out[2] = in[2];
	out[3] = in[3];
	out[4] = in[4];
	out[5] = in[5];
	out[6] = in[6];
	out[7] = in[7];
	out[8] = in[8];
	out[9] = in[9];
}

/* out = a + b */
__inline void
curve25519_add(bignum25519 out, const bignum25519 a, const bignum25519 b) {
	out[0] = a[0] + b[0];
	out[1] = a[1] + b[1];
	out[2] = a[2] + b[2];
	out[3] = a[3] + b[3];
	out[4] = a[4] + b[4];
	out[5] = a[5] + b[5];
	out[6] = a[6] + b[6];
	out[7] = a[7] + b[7];
	out[8] = a[8] + b[8];
	out[9] = a[9] + b[9];
}

__inline void 
curve25519_add_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b) {
	uint32_t c;
	out[0] = a[0] + b[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
	out[1] = a[1] + b[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
	out[2] = a[2] + b[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
	out[3] = a[3] + b[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
	out[4] = a[4] + b[4] + c; c = (out[4] >> 26); out[4] &= reduce_mask_26;
	out[5] = a[5] + b[5] + c; c = (out[5] >> 25); out[5] &= reduce_mask_25;
	out[6] = a[6] + b[6] + c; c = (out[6] >> 26); out[6] &= reduce_mask_26;
	out[7] = a[7] + b[7] + c; c = (out[7] >> 25); out[7] &= reduce_mask_25;
	out[8] = a[8] + b[8] + c; c = (out[8] >> 26); out[8] &= reduce_mask_26;
	out[9] = a[9] + b[9] + c; c = (out[9] >> 25); out[9] &= reduce_mask_25;
	out[0] += 19 * c;
}

__inline void
curve25519_add_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b) {
	uint32_t c;
	out[0] = a[0] + b[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
	out[1] = a[1] + b[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
	out[2] = a[2] + b[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
	out[3] = a[3] + b[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
	out[4] = a[4] + b[4] + c; c = (out[4] >> 26); out[4] &= reduce_mask_26;
	out[5] = a[5] + b[5] + c; c = (out[5] >> 25); out[5] &= reduce_mask_25;
	out[6] = a[6] + b[6] + c; c = (out[6] >> 26); out[6] &= reduce_mask_26;
	out[7] = a[7] + b[7] + c; c = (out[7] >> 25); out[7] &= reduce_mask_25;
	out[8] = a[8] + b[8] + c; c = (out[8] >> 26); out[8] &= reduce_mask_26;
	out[9] = a[9] + b[9] + c; c = (out[9] >> 25); out[9] &= reduce_mask_25;
	out[0] += 19 * c;
}

/* multiples of p */
__constant uint32_t twoP0       = 0x07ffffda;
__constant uint32_t twoP13579   = 0x03fffffe;
__constant uint32_t twoP2468    = 0x07fffffe;
__constant uint32_t fourP0      = 0x0fffffb4;
__constant uint32_t fourP13579  = 0x07fffffc;
__constant uint32_t fourP2468   = 0x0ffffffc;

/* out = a - b */
__inline void
curve25519_sub(bignum25519 out, const bignum25519 a, const bignum25519 b) {
	uint32_t c;
	out[0] = twoP0     + a[0] - b[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
	out[1] = twoP13579 + a[1] - b[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
	out[2] = twoP2468  + a[2] - b[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
	out[3] = twoP13579 + a[3] - b[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
	out[4] = twoP2468  + a[4] - b[4] + c;
	out[5] = twoP13579 + a[5] - b[5]    ;
	out[6] = twoP2468  + a[6] - b[6]    ;
	out[7] = twoP13579 + a[7] - b[7]    ;
	out[8] = twoP2468  + a[8] - b[8]    ;
	out[9] = twoP13579 + a[9] - b[9]    ;
}

/* out = a - b, where a is the result of a basic op (add,sub) */
__inline void
curve25519_sub_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b) {
	uint32_t c;
	out[0] = fourP0     + a[0] - b[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
	out[1] = fourP13579 + a[1] - b[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
	out[2] = fourP2468  + a[2] - b[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
	out[3] = fourP13579 + a[3] - b[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
	out[4] = fourP2468  + a[4] - b[4] + c; c = (out[4] >> 26); out[4] &= reduce_mask_26;
	out[5] = fourP13579 + a[5] - b[5] + c; c = (out[5] >> 25); out[5] &= reduce_mask_25;
	out[6] = fourP2468  + a[6] - b[6] + c; c = (out[6] >> 26); out[6] &= reduce_mask_26;
	out[7] = fourP13579 + a[7] - b[7] + c; c = (out[7] >> 25); out[7] &= reduce_mask_25;
	out[8] = fourP2468  + a[8] - b[8] + c; c = (out[8] >> 26); out[8] &= reduce_mask_26;
	out[9] = fourP13579 + a[9] - b[9] + c; c = (out[9] >> 25); out[9] &= reduce_mask_25;
	out[0] += 19 * c;
}

__inline void
curve25519_sub_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b) {
	uint32_t c;
	out[0] = fourP0     + a[0] - b[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
	out[1] = fourP13579 + a[1] - b[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
	out[2] = fourP2468  + a[2] - b[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
	out[3] = fourP13579 + a[3] - b[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
	out[4] = fourP2468  + a[4] - b[4] + c; c = (out[4] >> 26); out[4] &= reduce_mask_26;
	out[5] = fourP13579 + a[5] - b[5] + c; c = (out[5] >> 25); out[5] &= reduce_mask_25;
	out[6] = fourP2468  + a[6] - b[6] + c; c = (out[6] >> 26); out[6] &= reduce_mask_26;
	out[7] = fourP13579 + a[7] - b[7] + c; c = (out[7] >> 25); out[7] &= reduce_mask_25;
	out[8] = fourP2468  + a[8] - b[8] + c; c = (out[8] >> 26); out[8] &= reduce_mask_26;
	out[9] = fourP13579 + a[9] - b[9] + c; c = (out[9] >> 25); out[9] &= reduce_mask_25;
	out[0] += 19 * c;
}

/* out = -a */
__inline void
curve25519_neg(bignum25519 out, const bignum25519 a) {
	uint32_t c;
	out[0] = twoP0     - a[0]    ; c = (out[0] >> 26); out[0] &= reduce_mask_26;
	out[1] = twoP13579 - a[1] + c; c = (out[1] >> 25); out[1] &= reduce_mask_25;
	out[2] = twoP2468  - a[2] + c; c = (out[2] >> 26); out[2] &= reduce_mask_26;
	out[3] = twoP13579 - a[3] + c; c = (out[3] >> 25); out[3] &= reduce_mask_25;
	out[4] = twoP2468  - a[4] + c; c = (out[4] >> 26); out[4] &= reduce_mask_26;
	out[5] = twoP13579 - a[5] + c; c = (out[5] >> 25); out[5] &= reduce_mask_25;
	out[6] = twoP2468  - a[6] + c; c = (out[6] >> 26); out[6] &= reduce_mask_26;
	out[7] = twoP13579 - a[7] + c; c = (out[7] >> 25); out[7] &= reduce_mask_25;
	out[8] = twoP2468  - a[8] + c; c = (out[8] >> 26); out[8] &= reduce_mask_26;
	out[9] = twoP13579 - a[9] + c; c = (out[9] >> 25); out[9] &= reduce_mask_25;
	out[0] += 19 * c;
}

/* out = a * b */
#define curve25519_mul_noinline curve25519_mul
static void
curve25519_mul(bignum25519 out, const bignum25519 a, const bignum25519 b) {
	uint32_t r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
	uint32_t s0,s1,s2,s3,s4,s5,s6,s7,s8,s9;
	uint64_t m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,c;
	uint32_t p;

	r0 = b[0];
	r1 = b[1];
	r2 = b[2];
	r3 = b[3];
	r4 = b[4];
	r5 = b[5];
	r6 = b[6];
	r7 = b[7];
	r8 = b[8];
	r9 = b[9];

	s0 = a[0];
	s1 = a[1];
	s2 = a[2];
	s3 = a[3];
	s4 = a[4];
	s5 = a[5];
	s6 = a[6];
	s7 = a[7];
	s8 = a[8];
	s9 = a[9];

	m1 = mul32x32_64(r0, s1) + mul32x32_64(r1, s0);
	m3 = mul32x32_64(r0, s3) + mul32x32_64(r1, s2) + mul32x32_64(r2, s1) + mul32x32_64(r3, s0);
	m5 = mul32x32_64(r0, s5) + mul32x32_64(r1, s4) + mul32x32_64(r2, s3) + mul32x32_64(r3, s2) + mul32x32_64(r4, s1) + mul32x32_64(r5, s0);
	m7 = mul32x32_64(r0, s7) + mul32x32_64(r1, s6) + mul32x32_64(r2, s5) + mul32x32_64(r3, s4) + mul32x32_64(r4, s3) + mul32x32_64(r5, s2) + mul32x32_64(r6, s1) + mul32x32_64(r7, s0);
	m9 = mul32x32_64(r0, s9) + mul32x32_64(r1, s8) + mul32x32_64(r2, s7) + mul32x32_64(r3, s6) + mul32x32_64(r4, s5) + mul32x32_64(r5, s4) + mul32x32_64(r6, s3) + mul32x32_64(r7, s2) + mul32x32_64(r8, s1) + mul32x32_64(r9, s0);

	r1 *= 2;
	r3 *= 2;
	r5 *= 2;
	r7 *= 2;

	m0 = mul32x32_64(r0, s0);
	m2 = mul32x32_64(r0, s2) + mul32x32_64(r1, s1) + mul32x32_64(r2, s0);
	m4 = mul32x32_64(r0, s4) + mul32x32_64(r1, s3) + mul32x32_64(r2, s2) + mul32x32_64(r3, s1) + mul32x32_64(r4, s0);
	m6 = mul32x32_64(r0, s6) + mul32x32_64(r1, s5) + mul32x32_64(r2, s4) + mul32x32_64(r3, s3) + mul32x32_64(r4, s2) + mul32x32_64(r5, s1) + mul32x32_64(r6, s0);
	m8 = mul32x32_64(r0, s8) + mul32x32_64(r1, s7) + mul32x32_64(r2, s6) + mul32x32_64(r3, s5) + mul32x32_64(r4, s4) + mul32x32_64(r5, s3) + mul32x32_64(r6, s2) + mul32x32_64(r7, s1) + mul32x32_64(r8, s0);

	r1 *= 19;
	r2 *= 19;
	r3 = (r3 / 2) * 19;
	r4 *= 19;
	r5 = (r5 / 2) * 19;
	r6 *= 19;
	r7 = (r7 / 2) * 19;
	r8 *= 19;
	r9 *= 19;

	m1 += (mul32x32_64(r9, s2) + mul32x32_64(r8, s3) + mul32x32_64(r7, s4) + mul32x32_64(r6, s5) + mul32x32_64(r5, s6) + mul32x32_64(r4, s7) + mul32x32_64(r3, s8) + mul32x32_64(r2, s9));
	m3 += (mul32x32_64(r9, s4) + mul32x32_64(r8, s5) + mul32x32_64(r7, s6) + mul32x32_64(r6, s7) + mul32x32_64(r5, s8) + mul32x32_64(r4, s9));
	m5 += (mul32x32_64(r9, s6) + mul32x32_64(r8, s7) + mul32x32_64(r7, s8) + mul32x32_64(r6, s9));
	m7 += (mul32x32_64(r9, s8) + mul32x32_64(r8, s9));

	r3 *= 2;
	r5 *= 2;
	r7 *= 2;
	r9 *= 2;

	m0 += (mul32x32_64(r9, s1) + mul32x32_64(r8, s2) + mul32x32_64(r7, s3) + mul32x32_64(r6, s4) + mul32x32_64(r5, s5) + mul32x32_64(r4, s6) + mul32x32_64(r3, s7) + mul32x32_64(r2, s8) + mul32x32_64(r1, s9));
	m2 += (mul32x32_64(r9, s3) + mul32x32_64(r8, s4) + mul32x32_64(r7, s5) + mul32x32_64(r6, s6) + mul32x32_64(r5, s7) + mul32x32_64(r4, s8) + mul32x32_64(r3, s9));
	m4 += (mul32x32_64(r9, s5) + mul32x32_64(r8, s6) + mul32x32_64(r7, s7) + mul32x32_64(r6, s8) + mul32x32_64(r5, s9));
	m6 += (mul32x32_64(r9, s7) + mul32x32_64(r8, s8) + mul32x32_64(r7, s9));
	m8 += (mul32x32_64(r9, s9));

	                             r0 = (uint32_t)m0 & reduce_mask_26; c = (m0 >> 26);
	m1 += c;                     r1 = (uint32_t)m1 & reduce_mask_25; c = (m1 >> 25);
	m2 += c;                     r2 = (uint32_t)m2 & reduce_mask_26; c = (m2 >> 26);
	m3 += c;                     r3 = (uint32_t)m3 & reduce_mask_25; c = (m3 >> 25);
	m4 += c;                     r4 = (uint32_t)m4 & reduce_mask_26; c = (m4 >> 26);
	m5 += c;                     r5 = (uint32_t)m5 & reduce_mask_25; c = (m5 >> 25);
	m6 += c;                     r6 = (uint32_t)m6 & reduce_mask_26; c = (m6 >> 26);
	m7 += c;                     r7 = (uint32_t)m7 & reduce_mask_25; c = (m7 >> 25);
	m8 += c;                     r8 = (uint32_t)m8 & reduce_mask_26; c = (m8 >> 26);
	m9 += c;                     r9 = (uint32_t)m9 & reduce_mask_25; p = (uint32_t)(m9 >> 25);
	m0 = r0 + mul32x32_64(p,19); r0 = (uint32_t)m0 & reduce_mask_26; p = (uint32_t)(m0 >> 26);
	r1 += p;

	out[0] = r0;
	out[1] = r1;
	out[2] = r2;
	out[3] = r3;
	out[4] = r4;
	out[5] = r5;
	out[6] = r6;
	out[7] = r7;
	out[8] = r8;
	out[9] = r9;
}

static void
curve25519_mul_const(bignum25519 out, const bignum25519 a, constant uint32_t *b) {
	uint32_t r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
	uint32_t s0,s1,s2,s3,s4,s5,s6,s7,s8,s9;
	uint64_t m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,c;
	uint32_t p;

	r0 = b[0];
	r1 = b[1];
	r2 = b[2];
	r3 = b[3];
	r4 = b[4];
	r5 = b[5];
	r6 = b[6];
	r7 = b[7];
	r8 = b[8];
	r9 = b[9];

	s0 = a[0];
	s1 = a[1];
	s2 = a[2];
	s3 = a[3];
	s4 = a[4];
	s5 = a[5];
	s6 = a[6];
	s7 = a[7];
	s8 = a[8];
	s9 = a[9];

	m1 = mul32x32_64(r0, s1) + mul32x32_64(r1, s0);
	m3 = mul32x32_64(r0, s3) + mul32x32_64(r1, s2) + mul32x32_64(r2, s1) + mul32x32_64(r3, s0);
	m5 = mul32x32_64(r0, s5) + mul32x32_64(r1, s4) + mul32x32_64(r2, s3) + mul32x32_64(r3, s2) + mul32x32_64(r4, s1) + mul32x32_64(r5, s0);
	m7 = mul32x32_64(r0, s7) + mul32x32_64(r1, s6) + mul32x32_64(r2, s5) + mul32x32_64(r3, s4) + mul32x32_64(r4, s3) + mul32x32_64(r5, s2) + mul32x32_64(r6, s1) + mul32x32_64(r7, s0);
	m9 = mul32x32_64(r0, s9) + mul32x32_64(r1, s8) + mul32x32_64(r2, s7) + mul32x32_64(r3, s6) + mul32x32_64(r4, s5) + mul32x32_64(r5, s4) + mul32x32_64(r6, s3) + mul32x32_64(r7, s2) + mul32x32_64(r8, s1) + mul32x32_64(r9, s0);

	r1 *= 2;
	r3 *= 2;
	r5 *= 2;
	r7 *= 2;

	m0 = mul32x32_64(r0, s0);
	m2 = mul32x32_64(r0, s2) + mul32x32_64(r1, s1) + mul32x32_64(r2, s0);
	m4 = mul32x32_64(r0, s4) + mul32x32_64(r1, s3) + mul32x32_64(r2, s2) + mul32x32_64(r3, s1) + mul32x32_64(r4, s0);
	m6 = mul32x32_64(r0, s6) + mul32x32_64(r1, s5) + mul32x32_64(r2, s4) + mul32x32_64(r3, s3) + mul32x32_64(r4, s2) + mul32x32_64(r5, s1) + mul32x32_64(r6, s0);
	m8 = mul32x32_64(r0, s8) + mul32x32_64(r1, s7) + mul32x32_64(r2, s6) + mul32x32_64(r3, s5) + mul32x32_64(r4, s4) + mul32x32_64(r5, s3) + mul32x32_64(r6, s2) + mul32x32_64(r7, s1) + mul32x32_64(r8, s0);

	r1 *= 19;
	r2 *= 19;
	r3 = (r3 / 2) * 19;
	r4 *= 19;
	r5 = (r5 / 2) * 19;
	r6 *= 19;
	r7 = (r7 / 2) * 19;
	r8 *= 19;
	r9 *= 19;

	m1 += (mul32x32_64(r9, s2) + mul32x32_64(r8, s3) + mul32x32_64(r7, s4) + mul32x32_64(r6, s5) + mul32x32_64(r5, s6) + mul32x32_64(r4, s7) + mul32x32_64(r3, s8) + mul32x32_64(r2, s9));
	m3 += (mul32x32_64(r9, s4) + mul32x32_64(r8, s5) + mul32x32_64(r7, s6) + mul32x32_64(r6, s7) + mul32x32_64(r5, s8) + mul32x32_64(r4, s9));
	m5 += (mul32x32_64(r9, s6) + mul32x32_64(r8, s7) + mul32x32_64(r7, s8) + mul32x32_64(r6, s9));
	m7 += (mul32x32_64(r9, s8) + mul32x32_64(r8, s9));

	r3 *= 2;
	r5 *= 2;
	r7 *= 2;
	r9 *= 2;

	m0 += (mul32x32_64(r9, s1) + mul32x32_64(r8, s2) + mul32x32_64(r7, s3) + mul32x32_64(r6, s4) + mul32x32_64(r5, s5) + mul32x32_64(r4, s6) + mul32x32_64(r3, s7) + mul32x32_64(r2, s8) + mul32x32_64(r1, s9));
	m2 += (mul32x32_64(r9, s3) + mul32x32_64(r8, s4) + mul32x32_64(r7, s5) + mul32x32_64(r6, s6) + mul32x32_64(r5, s7) + mul32x32_64(r4, s8) + mul32x32_64(r3, s9));
	m4 += (mul32x32_64(r9, s5) + mul32x32_64(r8, s6) + mul32x32_64(r7, s7) + mul32x32_64(r6, s8) + mul32x32_64(r5, s9));
	m6 += (mul32x32_64(r9, s7) + mul32x32_64(r8, s8) + mul32x32_64(r7, s9));
	m8 += (mul32x32_64(r9, s9));

	                             r0 = (uint32_t)m0 & reduce_mask_26; c = (m0 >> 26);
	m1 += c;                     r1 = (uint32_t)m1 & reduce_mask_25; c = (m1 >> 25);
	m2 += c;                     r2 = (uint32_t)m2 & reduce_mask_26; c = (m2 >> 26);
	m3 += c;                     r3 = (uint32_t)m3 & reduce_mask_25; c = (m3 >> 25);
	m4 += c;                     r4 = (uint32_t)m4 & reduce_mask_26; c = (m4 >> 26);
	m5 += c;                     r5 = (uint32_t)m5 & reduce_mask_25; c = (m5 >> 25);
	m6 += c;                     r6 = (uint32_t)m6 & reduce_mask_26; c = (m6 >> 26);
	m7 += c;                     r7 = (uint32_t)m7 & reduce_mask_25; c = (m7 >> 25);
	m8 += c;                     r8 = (uint32_t)m8 & reduce_mask_26; c = (m8 >> 26);
	m9 += c;                     r9 = (uint32_t)m9 & reduce_mask_25; p = (uint32_t)(m9 >> 25);
	m0 = r0 + mul32x32_64(p,19); r0 = (uint32_t)m0 & reduce_mask_26; p = (uint32_t)(m0 >> 26);
	r1 += p;

	out[0] = r0;
	out[1] = r1;
	out[2] = r2;
	out[3] = r3;
	out[4] = r4;
	out[5] = r5;
	out[6] = r6;
	out[7] = r7;
	out[8] = r8;
	out[9] = r9;
}

/* out = in*in */
static void
curve25519_square(bignum25519 out, const bignum25519 in) {
	uint32_t r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
	uint32_t d6,d7,d8,d9;
	uint64_t m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,c;
	uint32_t p;

	r0 = in[0];
	r1 = in[1];
	r2 = in[2];
	r3 = in[3];
	r4 = in[4];
	r5 = in[5];
	r6 = in[6];
	r7 = in[7];
	r8 = in[8];
	r9 = in[9];

	m0 = mul32x32_64(r0, r0);
	r0 *= 2;
	m1 = mul32x32_64(r0, r1);
	m2 = mul32x32_64(r0, r2) + mul32x32_64(r1, r1 * 2);
	r1 *= 2;
	m3 = mul32x32_64(r0, r3) + mul32x32_64(r1, r2    );
	m4 = mul32x32_64(r0, r4) + mul32x32_64(r1, r3 * 2) + mul32x32_64(r2, r2);
	r2 *= 2;
	m5 = mul32x32_64(r0, r5) + mul32x32_64(r1, r4    ) + mul32x32_64(r2, r3);
	m6 = mul32x32_64(r0, r6) + mul32x32_64(r1, r5 * 2) + mul32x32_64(r2, r4) + mul32x32_64(r3, r3 * 2);
	r3 *= 2;
	m7 = mul32x32_64(r0, r7) + mul32x32_64(r1, r6    ) + mul32x32_64(r2, r5) + mul32x32_64(r3, r4    );
	m8 = mul32x32_64(r0, r8) + mul32x32_64(r1, r7 * 2) + mul32x32_64(r2, r6) + mul32x32_64(r3, r5 * 2) + mul32x32_64(r4, r4    );
	m9 = mul32x32_64(r0, r9) + mul32x32_64(r1, r8    ) + mul32x32_64(r2, r7) + mul32x32_64(r3, r6    ) + mul32x32_64(r4, r5 * 2);

	d6 = r6 * 19;
	d7 = r7 * 2 * 19;
	d8 = r8 * 19;
	d9 = r9 * 2 * 19;

	m0 += (mul32x32_64(d9, r1    ) + mul32x32_64(d8, r2    ) + mul32x32_64(d7, r3    ) + mul32x32_64(d6, r4 * 2) + mul32x32_64(r5, r5 * 2 * 19));
	m1 += (mul32x32_64(d9, r2 / 2) + mul32x32_64(d8, r3    ) + mul32x32_64(d7, r4    ) + mul32x32_64(d6, r5 * 2));
	m2 += (mul32x32_64(d9, r3    ) + mul32x32_64(d8, r4 * 2) + mul32x32_64(d7, r5 * 2) + mul32x32_64(d6, r6    ));
	m3 += (mul32x32_64(d9, r4    ) + mul32x32_64(d8, r5 * 2) + mul32x32_64(d7, r6    ));
	m4 += (mul32x32_64(d9, r5 * 2) + mul32x32_64(d8, r6 * 2) + mul32x32_64(d7, r7    ));
	m5 += (mul32x32_64(d9, r6    ) + mul32x32_64(d8, r7 * 2));
	m6 += (mul32x32_64(d9, r7 * 2) + mul32x32_64(d8, r8    ));
	m7 += (mul32x32_64(d9, r8    ));
	m8 += (mul32x32_64(d9, r9    ));

	                             r0 = (uint32_t)m0 & reduce_mask_26; c = (m0 >> 26);
	m1 += c;                     r1 = (uint32_t)m1 & reduce_mask_25; c = (m1 >> 25);
	m2 += c;                     r2 = (uint32_t)m2 & reduce_mask_26; c = (m2 >> 26);
	m3 += c;                     r3 = (uint32_t)m3 & reduce_mask_25; c = (m3 >> 25);
	m4 += c;                     r4 = (uint32_t)m4 & reduce_mask_26; c = (m4 >> 26);
	m5 += c;                     r5 = (uint32_t)m5 & reduce_mask_25; c = (m5 >> 25);
	m6 += c;                     r6 = (uint32_t)m6 & reduce_mask_26; c = (m6 >> 26);
	m7 += c;                     r7 = (uint32_t)m7 & reduce_mask_25; c = (m7 >> 25);
	m8 += c;                     r8 = (uint32_t)m8 & reduce_mask_26; c = (m8 >> 26);
	m9 += c;                     r9 = (uint32_t)m9 & reduce_mask_25; p = (uint32_t)(m9 >> 25);
	m0 = r0 + mul32x32_64(p,19); r0 = (uint32_t)m0 & reduce_mask_26; p = (uint32_t)(m0 >> 26);
	r1 += p;

	out[0] = r0;
	out[1] = r1;
	out[2] = r2;
	out[3] = r3;
	out[4] = r4;
	out[5] = r5;
	out[6] = r6;
	out[7] = r7;
	out[8] = r8;
	out[9] = r9;
}


/* out = in ^ (2 * count) */
static void
curve25519_square_times(bignum25519 out, const bignum25519 in, int count) {
	uint32_t r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
	uint32_t d6,d7,d8,d9;
	uint64_t m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,c;
	uint32_t p;

	r0 = in[0];
	r1 = in[1];
	r2 = in[2];
	r3 = in[3];
	r4 = in[4];
	r5 = in[5];
	r6 = in[6];
	r7 = in[7];
	r8 = in[8];
	r9 = in[9];

	do {
		m0 = mul32x32_64(r0, r0);
		r0 *= 2;
		m1 = mul32x32_64(r0, r1);
		m2 = mul32x32_64(r0, r2) + mul32x32_64(r1, r1 * 2);
		r1 *= 2;
		m3 = mul32x32_64(r0, r3) + mul32x32_64(r1, r2    );
		m4 = mul32x32_64(r0, r4) + mul32x32_64(r1, r3 * 2) + mul32x32_64(r2, r2);
		r2 *= 2;
		m5 = mul32x32_64(r0, r5) + mul32x32_64(r1, r4    ) + mul32x32_64(r2, r3);
		m6 = mul32x32_64(r0, r6) + mul32x32_64(r1, r5 * 2) + mul32x32_64(r2, r4) + mul32x32_64(r3, r3 * 2);
		r3 *= 2;
		m7 = mul32x32_64(r0, r7) + mul32x32_64(r1, r6    ) + mul32x32_64(r2, r5) + mul32x32_64(r3, r4    );
		m8 = mul32x32_64(r0, r8) + mul32x32_64(r1, r7 * 2) + mul32x32_64(r2, r6) + mul32x32_64(r3, r5 * 2) + mul32x32_64(r4, r4    );
		m9 = mul32x32_64(r0, r9) + mul32x32_64(r1, r8    ) + mul32x32_64(r2, r7) + mul32x32_64(r3, r6    ) + mul32x32_64(r4, r5 * 2);

		d6 = r6 * 19;
		d7 = r7 * 2 * 19;
		d8 = r8 * 19;
		d9 = r9 * 2 * 19;

		m0 += (mul32x32_64(d9, r1    ) + mul32x32_64(d8, r2    ) + mul32x32_64(d7, r3    ) + mul32x32_64(d6, r4 * 2) + mul32x32_64(r5, r5 * 2 * 19));
		m1 += (mul32x32_64(d9, r2 / 2) + mul32x32_64(d8, r3    ) + mul32x32_64(d7, r4    ) + mul32x32_64(d6, r5 * 2));
		m2 += (mul32x32_64(d9, r3    ) + mul32x32_64(d8, r4 * 2) + mul32x32_64(d7, r5 * 2) + mul32x32_64(d6, r6    ));
		m3 += (mul32x32_64(d9, r4    ) + mul32x32_64(d8, r5 * 2) + mul32x32_64(d7, r6    ));
		m4 += (mul32x32_64(d9, r5 * 2) + mul32x32_64(d8, r6 * 2) + mul32x32_64(d7, r7    ));
		m5 += (mul32x32_64(d9, r6    ) + mul32x32_64(d8, r7 * 2));
		m6 += (mul32x32_64(d9, r7 * 2) + mul32x32_64(d8, r8    ));
		m7 += (mul32x32_64(d9, r8    ));
		m8 += (mul32x32_64(d9, r9    ));

		                             r0 = (uint32_t)m0 & reduce_mask_26; c = (m0 >> 26);
		m1 += c;                     r1 = (uint32_t)m1 & reduce_mask_25; c = (m1 >> 25);
		m2 += c;                     r2 = (uint32_t)m2 & reduce_mask_26; c = (m2 >> 26);
		m3 += c;                     r3 = (uint32_t)m3 & reduce_mask_25; c = (m3 >> 25);
		m4 += c;                     r4 = (uint32_t)m4 & reduce_mask_26; c = (m4 >> 26);
		m5 += c;                     r5 = (uint32_t)m5 & reduce_mask_25; c = (m5 >> 25);
		m6 += c;                     r6 = (uint32_t)m6 & reduce_mask_26; c = (m6 >> 26);
		m7 += c;                     r7 = (uint32_t)m7 & reduce_mask_25; c = (m7 >> 25);
		m8 += c;                     r8 = (uint32_t)m8 & reduce_mask_26; c = (m8 >> 26);
		m9 += c;                     r9 = (uint32_t)m9 & reduce_mask_25; p = (uint32_t)(m9 >> 25);
		m0 = r0 + mul32x32_64(p,19); r0 = (uint32_t)m0 & reduce_mask_26; p = (uint32_t)(m0 >> 26);
		r1 += p;
	} while (--count);

	out[0] = r0;
	out[1] = r1;
	out[2] = r2;
	out[3] = r3;
	out[4] = r4;
	out[5] = r5;
	out[6] = r6;
	out[7] = r7;
	out[8] = r8;
	out[9] = r9;
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
static void
curve25519_expand(bignum25519 out, const unsigned char in[32]) {
	uint32_t x0,x1,x2,x3,x4,x5,x6,x7;

#if defined(__ENDIAN_LITTLE__)
	x0 = *(uint32_t *)(in + 0);
	x1 = *(uint32_t *)(in + 4);
	x2 = *(uint32_t *)(in + 8);
	x3 = *(uint32_t *)(in + 12);
	x4 = *(uint32_t *)(in + 16);
	x5 = *(uint32_t *)(in + 20);
	x6 = *(uint32_t *)(in + 24);
	x7 = *(uint32_t *)(in + 28);
#else
	#define F(s)                         \
		((((uint32_t)in[s + 0])      ) | \
		 (((uint32_t)in[s + 1]) <<  8) | \
		 (((uint32_t)in[s + 2]) << 16) | \
		 (((uint32_t)in[s + 3]) << 24))
	x0 = F(0);
	x1 = F(4);
	x2 = F(8);
	x3 = F(12);
	x4 = F(16);
	x5 = F(20);
	x6 = F(24);
	x7 = F(28);
	#undef F
#endif

	out[0] = (                        x0       ) & 0x3ffffff;
	out[1] = ((((uint64_t)x1 << 32) | x0) >> 26) & 0x1ffffff;
	out[2] = ((((uint64_t)x2 << 32) | x1) >> 19) & 0x3ffffff;
	out[3] = ((((uint64_t)x3 << 32) | x2) >> 13) & 0x1ffffff;
	out[4] = ((                       x3) >>  6) & 0x3ffffff;
	out[5] = (                        x4       ) & 0x1ffffff;
	out[6] = ((((uint64_t)x5 << 32) | x4) >> 25) & 0x3ffffff;
	out[7] = ((((uint64_t)x6 << 32) | x5) >> 19) & 0x1ffffff;
	out[8] = ((((uint64_t)x7 << 32) | x6) >> 12) & 0x3ffffff;
	out[9] = ((                       x7) >>  6) & 0x1ffffff;
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
static void
curve25519_contract(unsigned char out[32], const bignum25519 in) {
	bignum25519 f;
	curve25519_copy(f, in);

	#define carry_pass() \
		f[1] += f[0] >> 26; f[0] &= reduce_mask_26; \
		f[2] += f[1] >> 25; f[1] &= reduce_mask_25; \
		f[3] += f[2] >> 26; f[2] &= reduce_mask_26; \
		f[4] += f[3] >> 25; f[3] &= reduce_mask_25; \
		f[5] += f[4] >> 26; f[4] &= reduce_mask_26; \
		f[6] += f[5] >> 25; f[5] &= reduce_mask_25; \
		f[7] += f[6] >> 26; f[6] &= reduce_mask_26; \
		f[8] += f[7] >> 25; f[7] &= reduce_mask_25; \
		f[9] += f[8] >> 26; f[8] &= reduce_mask_26;

	#define carry_pass_full() \
		carry_pass() \
		f[0] += 19 * (f[9] >> 25); f[9] &= reduce_mask_25;

	#define carry_pass_final() \
		carry_pass() \
		f[9] &= reduce_mask_25;

	carry_pass_full()
	carry_pass_full()

	/* now t is between 0 and 2^255-1, properly carried. */
	/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */
	f[0] += 19;
	carry_pass_full()

	/* now between 19 and 2^255-1 in both cases, and offset by 19. */
	f[0] += (reduce_mask_26 + 1) - 19;
	f[1] += (reduce_mask_25 + 1) - 1;
	f[2] += (reduce_mask_26 + 1) - 1;
	f[3] += (reduce_mask_25 + 1) - 1;
	f[4] += (reduce_mask_26 + 1) - 1;
	f[5] += (reduce_mask_25 + 1) - 1;
	f[6] += (reduce_mask_26 + 1) - 1;
	f[7] += (reduce_mask_25 + 1) - 1;
	f[8] += (reduce_mask_26 + 1) - 1;
	f[9] += (reduce_mask_25 + 1) - 1;

	/* now between 2^255 and 2^256-20, and offset by 2^255. */
	carry_pass_final()

	#undef carry_pass
	#undef carry_full
	#undef carry_final

	f[1] <<= 2;
	f[2] <<= 3;
	f[3] <<= 5;
	f[4] <<= 6;
	f[6] <<= 1;
	f[7] <<= 3;
	f[8] <<= 4;
	f[9] <<= 6;

	#define F(i, s) \
		out[s+0] |= (unsigned char )(f[i] & 0xff); \
		out[s+1] = (unsigned char )((f[i] >> 8) & 0xff); \
		out[s+2] = (unsigned char )((f[i] >> 16) & 0xff); \
		out[s+3] = (unsigned char )((f[i] >> 24) & 0xff);

	out[0] = 0;
	out[16] = 0;
	F(0,0);
	F(1,3);
	F(2,6);
	F(3,9);
	F(4,12);
	F(5,16);
	F(6,19);
	F(7,22);
	F(8,25);
	F(9,28);
	#undef F
}


/* out = (flag) ? in : out */
__inline void
curve25519_move_conditional_bytes(uint8_t out[96], constant uint8_t *in, uint32_t flag) {
	const uint32_t nb = flag - 1, b = ~nb;
	constant uint32_t *inl = (constant uint32_t *)in;
	uint32_t *outl = (uint32_t *)out;
	outl[0] = (outl[0] & nb) | (inl[0] & b);
	outl[1] = (outl[1] & nb) | (inl[1] & b);
	outl[2] = (outl[2] & nb) | (inl[2] & b);
	outl[3] = (outl[3] & nb) | (inl[3] & b);
	outl[4] = (outl[4] & nb) | (inl[4] & b);
	outl[5] = (outl[5] & nb) | (inl[5] & b);
	outl[6] = (outl[6] & nb) | (inl[6] & b);
	outl[7] = (outl[7] & nb) | (inl[7] & b);
	outl[8] = (outl[8] & nb) | (inl[8] & b);
	outl[9] = (outl[9] & nb) | (inl[9] & b);
	outl[10] = (outl[10] & nb) | (inl[10] & b);
	outl[11] = (outl[11] & nb) | (inl[11] & b);
	outl[12] = (outl[12] & nb) | (inl[12] & b);
	outl[13] = (outl[13] & nb) | (inl[13] & b);
	outl[14] = (outl[14] & nb) | (inl[14] & b);
	outl[15] = (outl[15] & nb) | (inl[15] & b);
	outl[16] = (outl[16] & nb) | (inl[16] & b);
	outl[17] = (outl[17] & nb) | (inl[17] & b);
	outl[18] = (outl[18] & nb) | (inl[18] & b);
	outl[19] = (outl[19] & nb) | (inl[19] & b);
	outl[20] = (outl[20] & nb) | (inl[20] & b);
	outl[21] = (outl[21] & nb) | (inl[21] & b);
	outl[22] = (outl[22] & nb) | (inl[22] & b);
	outl[23] = (outl[23] & nb) | (inl[23] & b);

}

/* if (iswap) swap(a, b) */
__inline void
curve25519_swap_conditional(bignum25519 a, bignum25519 b, uint32_t iswap) {
	const uint32_t swap = (uint32_t)(-(int32_t)iswap);
	uint32_t x0,x1,x2,x3,x4,x5,x6,x7,x8,x9;

	x0 = swap & (a[0] ^ b[0]); a[0] ^= x0; b[0] ^= x0;
	x1 = swap & (a[1] ^ b[1]); a[1] ^= x1; b[1] ^= x1;
	x2 = swap & (a[2] ^ b[2]); a[2] ^= x2; b[2] ^= x2;
	x3 = swap & (a[3] ^ b[3]); a[3] ^= x3; b[3] ^= x3;
	x4 = swap & (a[4] ^ b[4]); a[4] ^= x4; b[4] ^= x4;
	x5 = swap & (a[5] ^ b[5]); a[5] ^= x5; b[5] ^= x5;
	x6 = swap & (a[6] ^ b[6]); a[6] ^= x6; b[6] ^= x6;
	x7 = swap & (a[7] ^ b[7]); a[7] ^= x7; b[7] ^= x7;
	x8 = swap & (a[8] ^ b[8]); a[8] ^= x8; b[8] ^= x8;
	x9 = swap & (a[9] ^ b[9]); a[9] ^= x9; b[9] ^= x9;
}


/*
	conversions
*/

__inline void
ge25519_p1p1_to_partial(ge25519 *r, const ge25519_p1p1 *p) {
	curve25519_mul(r->x, p->x, p->t);
	curve25519_mul(r->y, p->y, p->z);
	curve25519_mul(r->z, p->z, p->t); 
}

__inline void
ge25519_p1p1_to_full(ge25519 *r, const ge25519_p1p1 *p) {
	curve25519_mul(r->x, p->x, p->t);
	curve25519_mul(r->y, p->y, p->z);
	curve25519_mul(r->z, p->z, p->t); 
	curve25519_mul(r->t, p->x, p->y); 
}

static void
ge25519_full_to_pniels(ge25519_pniels *p, const ge25519 *r) {
	curve25519_sub(p->ysubx, r->y, r->x);
	curve25519_add(p->xaddy, r->y, r->x);
	curve25519_copy(p->z, r->z);
	curve25519_mul_const(p->t2d, r->t, ge25519_ec2d);
}

/*
	adding & doubling
*/

static void
ge25519_add_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519 *q) {
	bignum25519 a,b,c,d,t,u;

	curve25519_sub(a, p->y, p->x);
	curve25519_add(b, p->y, p->x);
	curve25519_sub(t, q->y, q->x);
	curve25519_add(u, q->y, q->x);
	curve25519_mul(a, a, t);
	curve25519_mul(b, b, u);
	curve25519_mul(c, p->t, q->t);
	curve25519_mul_const(c, c, ge25519_ec2d);
	curve25519_mul(d, p->z, q->z);
	curve25519_add(d, d, d);
	curve25519_sub(r->x, b, a);
	curve25519_add(r->y, b, a);
	curve25519_add_after_basic(r->z, d, c);
	curve25519_sub_after_basic(r->t, d, c);
}


static void
ge25519_double_p1p1(ge25519_p1p1 *r, const ge25519 *p) {
	bignum25519 a,b,c;

	curve25519_square(a, p->x);
	curve25519_square(b, p->y);
	curve25519_square(c, p->z);
	curve25519_add_reduce(c, c, c);
	curve25519_add(r->x, p->x, p->y);
	curve25519_square(r->x, r->x);
	curve25519_add(r->y, b, a);
	curve25519_sub(r->z, b, a);
	curve25519_sub_after_basic(r->x, r->x, r->y);
	curve25519_sub_after_basic(r->t, c, r->z);
}

static void
ge25519_nielsadd2_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_niels *q, unsigned char signbit) {
	const bignum25519 *qb = (const bignum25519 *)q;
	bignum25519 *rb = (bignum25519 *)r;
	bignum25519 a,b,c;

	curve25519_sub(a, p->y, p->x);
	curve25519_add(b, p->y, p->x);
	curve25519_mul(a, a, qb[signbit]); /* x for +, y for - */
	curve25519_mul(r->x, b, qb[signbit^1]); /* y for +, x for - */
	curve25519_add(r->y, r->x, a);
	curve25519_sub(r->x, r->x, a);
	curve25519_mul(c, p->t, q->t2d);
	curve25519_add_reduce(r->t, p->z, p->z);
	curve25519_copy(r->z, r->t);
	curve25519_add(rb[2+signbit], rb[2+signbit], c); /* z for +, t for - */
	curve25519_sub(rb[2+(signbit^1)], rb[2+(signbit^1)], c); /* t for +, z for - */
}

static void
ge25519_pnielsadd_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_pniels *q, unsigned char signbit) {
	const bignum25519 *qb = (const bignum25519 *)q;
	bignum25519 *rb = (bignum25519 *)r;
	bignum25519 a,b,c;

	curve25519_sub(a, p->y, p->x);
	curve25519_add(b, p->y, p->x);
	curve25519_mul(a, a, qb[signbit]); /* ysubx for +, xaddy for - */
	curve25519_mul(r->x, b, qb[signbit^1]); /* xaddy for +, ysubx for - */
	curve25519_add(r->y, r->x, a);
	curve25519_sub(r->x, r->x, a);
	curve25519_mul(c, p->t, q->t2d);
	curve25519_mul(r->t, p->z, q->z);
	curve25519_add_reduce(r->t, r->t, r->t);
	curve25519_copy(r->z, r->t);
	curve25519_add(rb[2+signbit], rb[2+signbit], c); /* z for +, t for - */
	curve25519_sub(rb[2+(signbit^1)], rb[2+(signbit^1)], c); /* t for +, z for - */
}

static void
ge25519_double_partial(ge25519 *r, const ge25519 *p) {
	ge25519_p1p1 t;
	ge25519_double_p1p1(&t, p);
	ge25519_p1p1_to_partial(r, &t);
}

static void
ge25519_double(ge25519 *r, const ge25519 *p) {
	ge25519_p1p1 t;
	ge25519_double_p1p1(&t, p);
	ge25519_p1p1_to_full(r, &t);
}

static void
ge25519_add(ge25519 *r, const ge25519 *p,  const ge25519 *q) {
	ge25519_p1p1 t;
	ge25519_add_p1p1(&t, p, q);
	ge25519_p1p1_to_full(r, &t);
}

static void
ge25519_nielsadd2(ge25519 *r, const ge25519_niels *q) {
	bignum25519 a,b,c,e,f,g,h;

	curve25519_sub(a, r->y, r->x);
	curve25519_add(b, r->y, r->x);
	curve25519_mul(a, a, q->ysubx);
	curve25519_mul(e, b, q->xaddy);
	curve25519_add(h, e, a);
	curve25519_sub(e, e, a);
	curve25519_mul(c, r->t, q->t2d);
	curve25519_add(f, r->z, r->z);
	curve25519_add_after_basic(g, f, c);
	curve25519_sub_after_basic(f, f, c);
	curve25519_mul(r->x, e, f);
	curve25519_mul(r->y, h, g);
	curve25519_mul(r->z, g, f);
	curve25519_mul(r->t, e, h);
}

static void
ge25519_pnielsadd(ge25519_pniels *r, const ge25519 *p, const ge25519_pniels *q) {
	bignum25519 a,b,c,x,y,z,t;

	curve25519_sub(a, p->y, p->x);
	curve25519_add(b, p->y, p->x);
	curve25519_mul(a, a, q->ysubx);
	curve25519_mul(x, b, q->xaddy);
	curve25519_add(y, x, a);
	curve25519_sub(x, x, a);
	curve25519_mul(c, p->t, q->t2d);
	curve25519_mul(t, p->z, q->z);
	curve25519_add(t, t, t);
	curve25519_add_after_basic(z, t, c);
	curve25519_sub_after_basic(t, t, c);
	curve25519_mul(r->xaddy, x, t);
	curve25519_mul(r->ysubx, y, z);
	curve25519_mul(r->z, z, t);
	curve25519_mul(r->t2d, x, y);
	curve25519_copy(y, r->ysubx);
	curve25519_sub(r->ysubx, r->ysubx, r->xaddy);
	curve25519_add(r->xaddy, r->xaddy, y);
	curve25519_mul_const(r->t2d, r->t2d, ge25519_ec2d);
}

/*
 * In:  b =   2^5 - 2^0
 * Out: b = 2^250 - 2^0
 */
static void
curve25519_pow_two5mtwo0_two250mtwo0(bignum25519 b) {
	bignum25519 ALIGN(16) t0,c;

	/* 2^5  - 2^0 */ /* b */
	/* 2^10 - 2^5 */ curve25519_square_times(t0, b, 5);
	/* 2^10 - 2^0 */ curve25519_mul_noinline(b, t0, b);
	/* 2^20 - 2^10 */ curve25519_square_times(t0, b, 10);
	/* 2^20 - 2^0 */ curve25519_mul_noinline(c, t0, b);
	/* 2^40 - 2^20 */ curve25519_square_times(t0, c, 20);
	/* 2^40 - 2^0 */ curve25519_mul_noinline(t0, t0, c);
	/* 2^50 - 2^10 */ curve25519_square_times(t0, t0, 10);
	/* 2^50 - 2^0 */ curve25519_mul_noinline(b, t0, b);
	/* 2^100 - 2^50 */ curve25519_square_times(t0, b, 50);
	/* 2^100 - 2^0 */ curve25519_mul_noinline(c, t0, b);
	/* 2^200 - 2^100 */ curve25519_square_times(t0, c, 100);
	/* 2^200 - 2^0 */ curve25519_mul_noinline(t0, t0, c);
	/* 2^250 - 2^50 */ curve25519_square_times(t0, t0, 50);
	/* 2^250 - 2^0 */ curve25519_mul_noinline(b, t0, b);
}

/*
 * z^(p - 2) = z(2^255 - 21)
 */
static void
curve25519_recip(bignum25519 out, const bignum25519 z) {
	bignum25519 ALIGN(16) a,t0,b;

	/* 2 */ curve25519_square_times(a, z, 1); /* a = 2 */
	/* 8 */ curve25519_square_times(t0, a, 2);
	/* 9 */ curve25519_mul_noinline(b, t0, z); /* b = 9 */
	/* 11 */ curve25519_mul_noinline(a, b, a); /* a = 11 */
	/* 22 */ curve25519_square_times(t0, a, 1);
	/* 2^5 - 2^0 = 31 */ curve25519_mul_noinline(b, t0, b);
	/* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
	/* 2^255 - 2^5 */ curve25519_square_times(b, b, 5);
	/* 2^255 - 21 */ curve25519_mul_noinline(out, b, a);
}

/*
 * z^((p-5)/8) = z^(2^252 - 3)
 */
static void
curve25519_pow_two252m3(bignum25519 two252m3, const bignum25519 z) {
	bignum25519 ALIGN(16) b,c,t0;

	/* 2 */ curve25519_square_times(c, z, 1); /* c = 2 */
	/* 8 */ curve25519_square_times(t0, c, 2); /* t0 = 8 */
	/* 9 */ curve25519_mul_noinline(b, t0, z); /* b = 9 */
	/* 11 */ curve25519_mul_noinline(c, b, c); /* c = 11 */
	/* 22 */ curve25519_square_times(t0, c, 1);
	/* 2^5 - 2^0 = 31 */ curve25519_mul_noinline(b, t0, b);
	/* 2^250 - 2^0 */ curve25519_pow_two5mtwo0_two250mtwo0(b);
	/* 2^252 - 2^2 */ curve25519_square_times(b, b, 2);
	/* 2^252 - 3 */ curve25519_mul_noinline(two252m3, b, z);
}


/*
	pack & unpack
*/

static void
ge25519_pack(unsigned char r[32], const ge25519 *p) {
	bignum25519 tx, ty, zi;
	unsigned char parity[32];
	curve25519_recip(zi, p->z);
	curve25519_mul(tx, p->x, zi);
	curve25519_mul(ty, p->y, zi);
	curve25519_contract(r, ty);
	curve25519_contract(parity, tx);
	r[31] ^= ((parity[0] & 1) << 7);
}

/*
	Timing safe memory compare
*/
static int
ed25519_verify(const unsigned char *x, const unsigned char *y, size_t len) {
	size_t differentbits = 0;
	while (len--)
		differentbits |= (*x++ ^ *y++);
	return (int) (1 & ((differentbits - 1) >> 8));
}

static int
ge25519_unpack_vartime(ge25519 *r, const unsigned char p[32]) {
	const unsigned char zero[32] = {0};
	const bignum25519 one = {1};
	unsigned char parity = p[31] >> 7;
	unsigned char check[32];
	bignum25519 t, root, num, den, d3;

	curve25519_expand(r->y, p);
	curve25519_copy(r->z, one);
	curve25519_square(num, r->y); /* x = y^2 */
	curve25519_mul_const(den, num, ge25519_ecd); /* den = dy^2 */
	curve25519_sub_reduce(num, num, r->z); /* x = y^1 - 1 */
	curve25519_add(den, den, r->z); /* den = dy^2 + 1 */

	/* Computation of sqrt(num/den) */
	/* 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8) */
	curve25519_square(t, den);
	curve25519_mul(d3, t, den);
	curve25519_square(r->x, d3);
	curve25519_mul(r->x, r->x, den);
	curve25519_mul(r->x, r->x, num);
	curve25519_pow_two252m3(r->x, r->x);

	/* 2. computation of r->x = num * den^3 * (num*den^7)^((p-5)/8) */
	curve25519_mul(r->x, r->x, d3);
	curve25519_mul(r->x, r->x, num);

	/* 3. Check if either of the roots works: */
	curve25519_square(t, r->x);
	curve25519_mul(t, t, den);
	curve25519_sub_reduce(root, t, num);
	curve25519_contract(check, root);
	if (!ed25519_verify(check, zero, 32)) {
		curve25519_add_reduce(t, t, num);
		curve25519_contract(check, t);
		if (!ed25519_verify(check, zero, 32))
			return 0;
		curve25519_mul_const(r->x, r->x, ge25519_sqrtneg1);
	}

	curve25519_contract(check, r->x);
	// Inverted from ge25519_unpack_negative_vartime
	if ((check[0] & 1) != parity) {
		curve25519_copy(t, r->x);
		curve25519_neg(r->x, t);
	}
	curve25519_mul(r->t, r->x, r->y);
	return 1;
}


/*
	scalarmults
*/

#define S1_SWINDOWSIZE 5
#define S1_TABLE_SIZE (1<<(S1_SWINDOWSIZE-2))
#define S2_SWINDOWSIZE 7
#define S2_TABLE_SIZE (1<<(S2_SWINDOWSIZE-2))

#if !defined(HAVE_GE25519_SCALARMULT_BASE_CHOOSE_NIELS)

static uint32_t
ge25519_windowb_equal(uint32_t b, uint32_t c) {
	return ((b ^ c) - 1) >> 31;
}

// modified to remove basepoint table argument
static void
ge25519_scalarmult_base_choose_niels(ge25519_niels *t, uint32_t pos, signed char b) {
	bignum25519 neg;
	uint32_t sign = (uint32_t)((unsigned char)b >> 7);
	uint32_t mask = ~(sign - 1);
	uint32_t u = (b + mask) ^ mask;
	uint32_t i;

	/* ysubx, xaddy, t2d in packed form. initialize to ysubx = 1, xaddy = 1, t2d = 0 */
	uint8_t packed[96] = {0};
	packed[0] = 1;
	packed[32] = 1;

	for (i = 0; i < 8; i++)
		curve25519_move_conditional_bytes(packed, ge25519_niels_base_multiples[(pos * 8) + i], ge25519_windowb_equal(u, i + 1));

	/* expand in to t */
	curve25519_expand(t->ysubx, packed +  0);
	curve25519_expand(t->xaddy, packed + 32);
	curve25519_expand(t->t2d  , packed + 64);

	/* adjust for sign */
	curve25519_swap_conditional(t->ysubx, t->xaddy, sign);
	curve25519_neg(neg, t->t2d);
	curve25519_swap_conditional(t->t2d, neg, sign);
}

#endif /* HAVE_GE25519_SCALARMULT_BASE_CHOOSE_NIELS */


/* computes [s]basepoint */
// modified to remove basepoint table argument
// and to work around the missing memset function
static void
ge25519_scalarmult_base_niels(ge25519 *r, const bignum256modm s) {
	signed char b[64];
	uint32_t i;
	ge25519_niels t;

	contract256_window4_modm(b, s);

	ge25519_scalarmult_base_choose_niels(&t, 0, b[1]);
	curve25519_sub_reduce(r->x, t.xaddy, t.ysubx);
	curve25519_add_reduce(r->y, t.xaddy, t.ysubx);
	// Original code: memset(r->z, 0, sizeof(bignum25519));
	// r->z is a bignum25519, i.e. a 10 element array
	for (size_t n = 0; n < 10; n++) r->z[n] = 0;
	curve25519_copy(r->t, t.t2d);
	r->z[0] = 2;	
	for (i = 3; i < 64; i += 2) {
		ge25519_scalarmult_base_choose_niels(&t, i / 2, b[i]);
		ge25519_nielsadd2(r, &t);
	}
	ge25519_double_partial(r, r);
	ge25519_double_partial(r, r);
	ge25519_double_partial(r, r);
	ge25519_double(r, r);
	ge25519_scalarmult_base_choose_niels(&t, 0, b[0]);
	curve25519_mul_const(t.t2d, t.t2d, ge25519_ecd);
	ge25519_nielsadd2(r, &t);
	for(i = 2; i < 64; i += 2) {
		ge25519_scalarmult_base_choose_niels(&t, i / 2, b[i]);
		ge25519_nielsadd2(r, &t);
	}
}

