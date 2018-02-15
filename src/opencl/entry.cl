__kernel void generate_pubkey (__global uchar *result, __global uchar *key_root, __global uchar *pub_req, __global uchar *pub_mask) {
	int const thread = get_global_id (0);
	uchar key[32];
	for (size_t i = 0; i < 32; i++) {
		key[i] = key_root[i];
	}
	*((size_t *) key) += thread;
	blake2b_state state;
	uchar hash[64];
	blake2b_init (&state, sizeof (hash));
	blake2b_update (&state, key, 32);
	blake2b_final (&state, hash, sizeof (hash));
	hash[0] &= 248;
	hash[31] &= 127;
	hash[31] |= 64;
	bignum256modm a;
	ge25519 ALIGN(16) A;
	expand256_modm(a, (uchar *) &hash, 32);
	ge25519_scalarmult_base_niels(&A, a);
	uchar pubkey[32];
	ge25519_pack(pubkey, &A);
	for (size_t i = 0; i < 32; i++) {
		if ((pubkey[i] & pub_mask[i]) != pub_req[i]) {
			return;
		}
	}
	for (size_t i = 0; i < 32; i++) {
		result[i] = key[i];
	}
}
