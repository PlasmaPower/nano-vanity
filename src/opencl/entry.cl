inline void generate_checksum (uchar checksum[5], const uchar pubkey[32]) {
	// For some reason, this doesn't work when put in generate_pubkey.
	blake2b_state state;
	blake2b_init (&state, 5);
	blake2b_update (&state, (__private uchar *) pubkey, 32);
	blake2b_final (&state, (__private uchar *) checksum, 5);
}

__kernel void generate_pubkey (__global uint64_t *result, __global uchar *key_root, __global uchar *pub_req, __global uchar *pub_mask, uchar prefix_len, uchar generate_key_type, __global uchar *public_offset) {
	size_t const thread = get_global_id (0);
	uchar key[32];
	for (size_t i = 0; i < 32; i++) {
		key[i] = key_root[i];
	}
	*((size_t *) key) += thread;
	if (generate_key_type == 1) {
		// seed
		blake2b_state keystate;
		blake2b_init (&keystate, sizeof (key));
		blake2b_update (&keystate, key, sizeof (key));
		uint32_t idx = 0;
		blake2b_update (&keystate, (uchar *) &idx, 4);
		blake2b_final (&keystate, key, sizeof (key));
	}
	blake2b_state state;
	bignum256modm a;
	ge25519 ALIGN(16) A;
	if (generate_key_type != 2) {
		// key is an ed25519 private key
		uchar hash[64];
		blake2b_init (&state, sizeof (hash));
		blake2b_update (&state, key, 32);
		blake2b_final (&state, hash, sizeof (hash));
		hash[0] &= 248;
		hash[31] &= 127;
		hash[31] |= 64;
		expand256_modm(a, hash, 32);
	} else {
		// key is a scalar
		expand256_modm(a, key, 32);
	}
	ge25519_scalarmult_base_niels(&A, a);
	if (generate_key_type == 2) {
		uchar public_offset_copy[32];
		for (size_t i = 0; i < 32; i++) {
			public_offset_copy[i] = public_offset[i];
		}
		ge25519 ALIGN(16) public_offset_curvepoint;
		ge25519_unpack_vartime(&public_offset_curvepoint, public_offset_copy);
		ge25519_add(&A, &A, &public_offset_curvepoint);
	}
	uchar pubkey[32];
	ge25519_pack(pubkey, &A);
	uchar pubkey_prefix_len = prefix_len;
	if (pubkey_prefix_len > 32) {
		pubkey_prefix_len = 32;
	}
	for (uchar i = 0; i < pubkey_prefix_len; i++) {
		if ((pubkey[i] & pub_mask[i]) != pub_req[i]) {
			return;
		}
	}
	if (prefix_len > 32) {
		uchar checksum[5];
		generate_checksum (checksum, pubkey);
		for (uchar i = 32; i < prefix_len; i++) {
			if ((checksum[4 - (i - 32)] & pub_mask[i]) != pub_req[i]) {
				return;
			}
		}
	}
	*result = thread;
}
