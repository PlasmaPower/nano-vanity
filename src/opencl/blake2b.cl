// Taken from raiblock's openclwork.cpp

enum blake2b_constant
{
	BLAKE2B_BLOCKBYTES = 128,
	BLAKE2B_OUTBYTES   = 64,
	BLAKE2B_KEYBYTES   = 64,
	BLAKE2B_SALTBYTES  = 16,
	BLAKE2B_PERSONALBYTES = 16
};

typedef struct __blake2b_param
{
	uchar  digest_length; // 1
	uchar  key_length;    // 2
	uchar  fanout;        // 3
	uchar  depth;         // 4
	uint leaf_length;   // 8
	ulong node_offset;   // 16
	uchar  node_depth;    // 17
	uchar  inner_length;  // 18
	uchar  reserved[14];  // 32
	uchar  salt[BLAKE2B_SALTBYTES]; // 48
	uchar  personal[BLAKE2B_PERSONALBYTES];  // 64
} blake2b_param;

typedef struct __blake2b_state
{
	ulong h[8];
	ulong t[2];
	ulong f[2];
	uchar  buf[2 * BLAKE2B_BLOCKBYTES];
	size_t   buflen;
	uchar  last_node;
} blake2b_state;

__constant static ulong blake2b_IV[8] =
{
	0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
	0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
	0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
	0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
};

__constant static uchar blake2b_sigma[12][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};


static inline int blake2b_set_lastnode( blake2b_state *S )
{
  S->f[1] = ~0UL;
  return 0;
}

/* Some helper functions, not necessarily useful */
static inline int blake2b_set_lastblock( blake2b_state *S )
{
  if( S->last_node ) blake2b_set_lastnode( S );

  S->f[0] = ~0UL;
  return 0;
}

static inline int blake2b_increment_counter( blake2b_state *S, const ulong inc )
{
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
  return 0;
}

static inline uint load32( const void *src )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  return *( uint * )( src );
#else
  const uchar *p = ( uchar * )src;
  uint w = *p++;
  w |= ( uint )( *p++ ) <<  8;
  w |= ( uint )( *p++ ) << 16;
  w |= ( uint )( *p++ ) << 24;
  return w;
#endif
}

static inline ulong load64( const void *src )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  return *( ulong * )( src );
#else
  const uchar *p = ( uchar * )src;
  ulong w = *p++;
  w |= ( ulong )( *p++ ) <<  8;
  w |= ( ulong )( *p++ ) << 16;
  w |= ( ulong )( *p++ ) << 24;
  w |= ( ulong )( *p++ ) << 32;
  w |= ( ulong )( *p++ ) << 40;
  w |= ( ulong )( *p++ ) << 48;
  w |= ( ulong )( *p++ ) << 56;
  return w;
#endif
}

static inline void store32( void *dst, uint w )
{
#if defined(__ENDIAN_LITTLE__)
  *( uint * )( dst ) = w;
#else
  uchar *p = ( uchar * )dst;
  *p++ = ( uchar )w; w >>= 8;
  *p++ = ( uchar )w; w >>= 8;
  *p++ = ( uchar )w; w >>= 8;
  *p++ = ( uchar )w;
#endif
}

static inline void store64( void *dst, ulong w )
{
#if defined(__ENDIAN_LITTLE__)
  *( ulong * )( dst ) = w;
#else
  uchar *p = ( uchar * )dst;
  *p++ = ( uchar )w; w >>= 8;
  *p++ = ( uchar )w; w >>= 8;
  *p++ = ( uchar )w; w >>= 8;
  *p++ = ( uchar )w; w >>= 8;
  *p++ = ( uchar )w; w >>= 8;
  *p++ = ( uchar )w; w >>= 8;
  *p++ = ( uchar )w; w >>= 8;
  *p++ = ( uchar )w;
#endif
}

static inline ulong rotr64( const ulong w, const unsigned c )
{
  return ( w >> c ) | ( w << ( 64 - c ) );
}

static void ucharset (void * dest_a, int val, size_t count)
{
	uchar * dest = (uchar *)dest_a;
	for (size_t i = 0; i < count; ++i)
	{
		*dest++ = val;
	}
}

/* init xors IV with input parameter block */
static inline int blake2b_init_param( blake2b_state *S, const blake2b_param *P )
{
  uchar *p, *h;
  __constant uchar *v;
  v = ( __constant uchar * )( blake2b_IV );
  h = ( uchar * )( S->h );
  p = ( uchar * )( P );
  /* IV XOR ParamBlock */
  ucharset( S, 0, sizeof( blake2b_state ) );

  for( int i = 0; i < BLAKE2B_OUTBYTES; ++i ) h[i] = v[i] ^ p[i];

  return 0;
}

static inline int blake2b_init( blake2b_state *S, const uchar outlen )
{
  blake2b_param P[1];

  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) return -1;

  P->digest_length = outlen;
  P->key_length    = 0;
  P->fanout        = 1;
  P->depth         = 1;
  store32( &P->leaf_length, 0 );
  store64( &P->node_offset, 0 );
  P->node_depth    = 0;
  P->inner_length  = 0;
  ucharset( P->reserved, 0, sizeof( P->reserved ) );
  ucharset( P->salt,     0, sizeof( P->salt ) );
  ucharset( P->personal, 0, sizeof( P->personal ) );
  return blake2b_init_param( S, P );
}

static int blake2b_compress( blake2b_state *S, __private const uchar block[BLAKE2B_BLOCKBYTES] )
{
  ulong m[16];
  ulong v[16];
  int i;

  for( i = 0; i < 16; ++i )
	m[i] = load64( block + i * sizeof( m[i] ) );

  for( i = 0; i < 8; ++i )
	v[i] = S->h[i];

  v[ 8] = blake2b_IV[0];
  v[ 9] = blake2b_IV[1];
  v[10] = blake2b_IV[2];
  v[11] = blake2b_IV[3];
  v[12] = S->t[0] ^ blake2b_IV[4];
  v[13] = S->t[1] ^ blake2b_IV[5];
  v[14] = S->f[0] ^ blake2b_IV[6];
  v[15] = S->f[1] ^ blake2b_IV[7];
#define G(r,i,a,b,c,d) \
  do { \
	a = a + b + m[blake2b_sigma[r][2*i+0]]; \
	d = rotr64(d ^ a, 32); \
	c = c + d; \
	b = rotr64(b ^ c, 24); \
	a = a + b + m[blake2b_sigma[r][2*i+1]]; \
	d = rotr64(d ^ a, 16); \
	c = c + d; \
	b = rotr64(b ^ c, 63); \
  } while(0)
#define ROUND(r)  \
  do { \
	G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
	G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
	G(r,2,v[ 2],v[ 6],v[10],v[14]); \
	G(r,3,v[ 3],v[ 7],v[11],v[15]); \
	G(r,4,v[ 0],v[ 5],v[10],v[15]); \
	G(r,5,v[ 1],v[ 6],v[11],v[12]); \
	G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
	G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)
  ROUND( 0 );
  ROUND( 1 );
  ROUND( 2 );
  ROUND( 3 );
  ROUND( 4 );
  ROUND( 5 );
  ROUND( 6 );
  ROUND( 7 );
  ROUND( 8 );
  ROUND( 9 );
  ROUND( 10 );
  ROUND( 11 );

  for( i = 0; i < 8; ++i )
	S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
  return 0;
}

static void ucharcpy (uchar * dst, uchar const * src, size_t count)
{
	for (size_t i = 0; i < count; ++i)
	{
		*dst++ = *src++;
	}
}

void printstate (blake2b_state * S)
{
	printf ("%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu ", S->h[0], S->h[1], S->h[2], S->h[3], S->h[4], S->h[5], S->h[6], S->h[7], S->t[0], S->t[1], S->f[0], S->f[1]);
	for (int i = 0; i < 128; ++i)
	{
		printf ("%02x", S->buf[i]);
	}
	printf (" %lu %02x\n", S->buflen, S->last_node);
}

/* inlen now in bytes */
static int blake2b_update( blake2b_state *S, const uchar *in, ulong inlen )
{
  while( inlen > 0 )
  {
	size_t left = S->buflen;
	size_t fill = 2 * BLAKE2B_BLOCKBYTES - left;

	if( inlen > fill )
	{
	  ucharcpy( S->buf + left, in, fill ); // Fill buffer
	  S->buflen += fill;
	  blake2b_increment_counter( S, BLAKE2B_BLOCKBYTES );
	  blake2b_compress( S, S->buf ); // Compress
	  ucharcpy( S->buf, S->buf + BLAKE2B_BLOCKBYTES, BLAKE2B_BLOCKBYTES ); // Shift buffer left
	  S->buflen -= BLAKE2B_BLOCKBYTES;
	  in += fill;
	  inlen -= fill;
	}
	else // inlen <= fill
	{
	  ucharcpy( S->buf + left, in, inlen );
	  S->buflen += inlen; // Be lazy, do not compress
	  in += inlen;
	  inlen -= inlen;
	}
  }

  return 0;
}

static int blake2b_final( blake2b_state *S, uchar *out, uchar outlen )
{
  uchar buffer[BLAKE2B_OUTBYTES];

  if( S->buflen > BLAKE2B_BLOCKBYTES )
  {
	blake2b_increment_counter( S, BLAKE2B_BLOCKBYTES );
	blake2b_compress( S, S->buf );
	S->buflen -= BLAKE2B_BLOCKBYTES;
	ucharcpy( S->buf, S->buf + BLAKE2B_BLOCKBYTES, S->buflen );
  }

  //blake2b_increment_counter( S, S->buflen );
  ulong inc = (ulong)S->buflen;
  S->t[0] += inc;
//  if ( S->t[0] < inc )
//    S->t[1] += 1;
  // This seems to crash the opencl compiler though fortunately this is calculating size and we don't do things bigger than 2^32

  blake2b_set_lastblock( S );
  ucharset( S->buf + S->buflen, 0, 2 * BLAKE2B_BLOCKBYTES - S->buflen ); /* Padding */
  blake2b_compress( S, S->buf );

  for( int i = 0; i < 8; ++i ) /* Output full hash to temp buffer */
	store64( buffer + sizeof( S->h[i] ) * i, S->h[i] );

  ucharcpy( out, buffer, outlen );
  return 0;
}

static void ucharcpyglb (uchar * dst, __global uchar const * src, size_t count)
{
	for (size_t i = 0; i < count; ++i)
	{
		*dst = *src;
		++dst;
		++src;
	}
}
