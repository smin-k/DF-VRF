/*
 * Epervier wrapper for the root Falcon C implementation.
 * This keeps the 16-bit public-key and signature packing used by the
 * original epervier layout, while relying only on the local Falcon tree.
 */

#include <stddef.h>
#include <string.h>

#include "falcon.h"
#include "inner.h"

#define EPERVIER_LOGN 9
#define EPERVIER_N (1u << EPERVIER_LOGN)
#define EPERVIER_PUBKEY_SIZE 1025
#define EPERVIER_NONCE_SIZE 40
#define EPERVIER_SIG_BODY_SIZE 1026
#define EPERVIER_SECRETKEYBYTES FALCON_PRIVKEY_SIZE(EPERVIER_LOGN)

static size_t
ep_modq_encode16(void *out, size_t max_out_len, const uint16_t *x, unsigned logn)
{
	size_t n, out_len, u;
	uint8_t *buf;
	uint32_t acc;
	int acc_len;

	n = (size_t)1 << logn;
	for (u = 0; u < n; u++) {
		if (x[u] >= 12289) {
			return 0;
		}
	}
	out_len = ((n * 16) + 7) >> 3;
	if (out == NULL) {
		return out_len;
	}
	if (out_len > max_out_len) {
		return 0;
	}
	buf = (uint8_t *)out;
	acc = 0;
	acc_len = 0;
	for (u = 0; u < n; u++) {
		acc = (acc << 16) | x[u];
		acc_len += 16;
		while (acc_len >= 8) {
			acc_len -= 8;
			*buf++ = (uint8_t)(acc >> acc_len);
		}
	}
	if (acc_len > 0) {
		*buf = (uint8_t)(acc << (8 - acc_len));
	}
	return out_len;
}

static size_t
ep_modq_decode16(uint16_t *x, unsigned logn, const void *in, size_t max_in_len)
{
	size_t n, in_len, u;
	const uint8_t *buf;
	uint32_t acc;
	int acc_len;

	n = (size_t)1 << logn;
	in_len = ((n * 16) + 7) >> 3;
	if (in_len > max_in_len) {
		return 0;
	}
	buf = (const uint8_t *)in;
	acc = 0;
	acc_len = 0;
	u = 0;
	while (u < n) {
		acc = (acc << 8) | (*buf++);
		acc_len += 8;
		if (acc_len >= 16) {
			int16_t w;

			acc_len -= 16;
			w = (int16_t)((acc >> acc_len) & 0xFFFF);
			if (w >= 12289) {
				return 0;
			}
			w -= 12289 & ~((w - 2047) >> 31);
			x[u++] = (uint16_t)w;
		}
	}
	if ((acc & (((uint32_t)1 << acc_len) - 1)) != 0) {
		return 0;
	}
	return in_len;
}

static size_t
ep_comp_encode16(void *out, size_t max_out_len, const int16_t *x, unsigned logn)
{
	size_t n, out_len, u;
	uint8_t *buf;
	uint32_t acc;
	int acc_len;

	n = (size_t)1 << logn;
	for (u = 0; u < n; u++) {
		if (x[u] >= 12289 || x[u] <= -12289) {
			return 0;
		}
	}
	out_len = ((n * 16) + 7) >> 3;
	if (out == NULL) {
		return out_len;
	}
	if (out_len > max_out_len) {
		return 0;
	}
	buf = (uint8_t *)out;
	acc = 0;
	acc_len = 0;
	for (u = 0; u < n; u++) {
		acc = (acc << 16) | (uint32_t)(x[u] + ((x[u] >> 31) & 12289));
		acc_len += 16;
		while (acc_len >= 8) {
			acc_len -= 8;
			*buf++ = (uint8_t)(acc >> acc_len);
		}
	}
	if (acc_len > 0) {
		*buf = (uint8_t)(acc << (8 - acc_len));
	}
	return out_len;
}

static size_t
ep_comp_decode16(int16_t *x, unsigned logn, const void *in, size_t max_in_len)
{
	size_t n, in_len, u;
	const uint8_t *buf;
	uint32_t acc;
	int acc_len;

	n = (size_t)1 << logn;
	in_len = ((n * 16) + 7) >> 3;
	if (in_len > max_in_len) {
		return 0;
	}
	buf = (const uint8_t *)in;
	acc = 0;
	acc_len = 0;
	u = 0;
	while (u < n) {
		acc = (acc << 8) | (*buf++);
		acc_len += 8;
		if (acc_len >= 16) {
			int16_t w;

			acc_len -= 16;
			w = (int16_t)((acc >> acc_len) & 0xFFFF);
			if (w >= 12289) {
				return 0;
			}
			w -= 12289 & ~((w - 2047) >> 31);
			x[u++] = w;
		}
	}
	if ((acc & (((uint32_t)1 << acc_len) - 1)) != 0) {
		return 0;
	}
	return in_len;
}

int
zknox_pk_epervier(unsigned char *pk)
{
	uint16_t h[EPERVIER_N];
	size_t v;

	if (pk[0] != 0x00 + EPERVIER_LOGN) {
		return -1;
	}
	if (ep_modq_decode16(h, EPERVIER_LOGN, pk + 1, EPERVIER_PUBKEY_SIZE - 1) != EPERVIER_PUBKEY_SIZE - 1) {
		return -1;
	}
	Zf(to_ntt)(h, EPERVIER_LOGN);
	pk[0] = 0x00 + EPERVIER_LOGN;
	v = ep_modq_encode16(pk + 1, EPERVIER_PUBKEY_SIZE - 1, h, EPERVIER_LOGN);
	if (v != EPERVIER_PUBKEY_SIZE - 1) {
		return -1;
	}
	return 0;
}

int
zknox_crypto_sign_epervier(unsigned char *sm, unsigned long long *smlen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk)
{
	typedef union {
		uint8_t b[72 * EPERVIER_N];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp_u;
	tmp_u tmp;
	int8_t f[EPERVIER_N], g[EPERVIER_N], F[EPERVIER_N], G[EPERVIER_N];
	uint16_t hm[EPERVIER_N];
	int16_t s1[EPERVIER_N], s2[EPERVIER_N], hint;
	unsigned char seed[48], nonce[EPERVIER_NONCE_SIZE];
	unsigned char esig[2 + EPERVIER_SIG_BODY_SIZE + 2 + EPERVIER_SIG_BODY_SIZE];
	inner_shake256_context sc;
	size_t u, v, sig_len, s2_len;

	if (sk[0] != 0x50 + EPERVIER_LOGN) {
		return -1;
	}
	u = 1;
	v = Zf(trim_i8_decode)(f, EPERVIER_LOGN, Zf(max_fg_bits)[EPERVIER_LOGN], sk + u, EPERVIER_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_decode)(g, EPERVIER_LOGN, Zf(max_fg_bits)[EPERVIER_LOGN], sk + u, EPERVIER_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_decode)(F, EPERVIER_LOGN, Zf(max_FG_bits)[EPERVIER_LOGN], sk + u, EPERVIER_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	if (u != EPERVIER_SECRETKEYBYTES) {
		return -1;
	}
	if (!Zf(complete_private)(G, f, g, F, EPERVIER_LOGN, tmp.b)) {
		return -1;
	}
	if (!Zf(get_seed)(nonce, sizeof nonce)) {
		return -1;
	}

	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, nonce, sizeof nonce);
	inner_shake256_inject(&sc, m, mlen);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, hm, EPERVIER_LOGN);

	if (!Zf(get_seed)(seed, sizeof seed)) {
		return -1;
	}
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, seed, sizeof seed);
	inner_shake256_flip(&sc);

	do {
		Zf(sign_dyn)(s2, &sc, f, g, F, G, hm, EPERVIER_LOGN, tmp.b);
		memcpy(s1, tmp.b, sizeof s1);
	} while (!Zf(is_invertible)(s2, EPERVIER_LOGN, tmp.b));

	esig[0] = 0x20 + EPERVIER_LOGN;
	sig_len = ep_comp_encode16(esig + 1, EPERVIER_SIG_BODY_SIZE, s1, EPERVIER_LOGN);
	if (sig_len == 0) {
		return -1;
	}
	sig_len++;
	esig[sig_len] = 0x20 + EPERVIER_LOGN;
	s2_len = ep_comp_encode16(esig + sig_len + 1, EPERVIER_SIG_BODY_SIZE, s2, EPERVIER_LOGN);
	if (s2_len == 0) {
		return -1;
	}
	sig_len += s2_len;
	sig_len++;
	hint = (int16_t)Zf(hint_epervier)(s2, EPERVIER_LOGN);
	sig_len += 2;

	memmove(sm + 2 + EPERVIER_NONCE_SIZE, m, mlen);
	sm[0] = (unsigned char)(sig_len >> 8);
	sm[1] = (unsigned char)sig_len;
	memcpy(sm + 2, nonce, EPERVIER_NONCE_SIZE);
	memcpy(sm + 2 + EPERVIER_NONCE_SIZE + mlen, esig, sig_len - 2);
	sm[2 + EPERVIER_NONCE_SIZE + mlen + sig_len - 2] = (unsigned char)(hint >> 8);
	sm[2 + EPERVIER_NONCE_SIZE + mlen + sig_len - 1] = (unsigned char)hint;
	*smlen = 2 + EPERVIER_NONCE_SIZE + mlen + sig_len;
	return 0;
}

int
zknox_crypto_sign_open_epervier(unsigned char *m, unsigned long long *mlen,
	const unsigned char *sm, unsigned long long smlen,
	const unsigned char *pk)
{
	typedef union {
		uint8_t b[2 * EPERVIER_N];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp_u;
	tmp_u tmp;
	const unsigned char *esig;
	uint16_t h[EPERVIER_N], h2[EPERVIER_N], hm[EPERVIER_N];
	int16_t s1[EPERVIER_N], s2[EPERVIER_N];
	inner_shake256_context sc;
	size_t sig_len, msg_len;
	unsigned i;

	if (pk[0] != 0x00 + EPERVIER_LOGN) {
		return -1;
	}
	if (ep_modq_decode16(h, EPERVIER_LOGN, pk + 1, EPERVIER_PUBKEY_SIZE - 1) != EPERVIER_PUBKEY_SIZE - 1) {
		return -1;
	}
	if (smlen < 2 + EPERVIER_NONCE_SIZE) {
		return -1;
	}
	sig_len = ((size_t)sm[0] << 8) | (size_t)sm[1];
	if (sig_len > (smlen - 2 - EPERVIER_NONCE_SIZE)) {
		return -1;
	}
	msg_len = smlen - 2 - EPERVIER_NONCE_SIZE - sig_len;
	esig = sm + 2 + EPERVIER_NONCE_SIZE + msg_len;
	if (sig_len < 1 || esig[0] != 0x20 + EPERVIER_LOGN || esig[1025] != 0x20 + EPERVIER_LOGN) {
		return -1;
	}
	if (ep_comp_decode16(s1, EPERVIER_LOGN, esig + 1, EPERVIER_SIG_BODY_SIZE) != EPERVIER_SIG_BODY_SIZE) {
		return -1;
	}
	if (ep_comp_decode16(s2, EPERVIER_LOGN, esig + 1 + EPERVIER_SIG_BODY_SIZE + 1, EPERVIER_SIG_BODY_SIZE) != EPERVIER_SIG_BODY_SIZE) {
		return -1;
	}

	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, sm + 2, EPERVIER_NONCE_SIZE + msg_len);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, hm, EPERVIER_LOGN);

	if (!Zf(verify_recover_epervier)(h2, hm, s1, s2, EPERVIER_LOGN, tmp.b)) {
		return -1;
	}
	for (i = 0; i < EPERVIER_N; i++) {
		if (h[i] != h2[i]) {
			return -1;
		}
	}

	memmove(m, sm + 2 + EPERVIER_NONCE_SIZE, msg_len);
	*mlen = msg_len;
	return 0;
}