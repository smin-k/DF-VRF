#include <string.h>
#include "inner.h"

/* Expose the forward NTT (mod q, no Montgomery) for Go bindings. */
void falcon_ntt_forward(uint16_t *h, unsigned logn) {
	Zf(mq_NTT)(h, logn);
}

/*
 * Decode s2 coefficients from a Keccak-mode Falcon-512 compressed signature.
 * Format: [header:1][nonce:40][compressed_s2:variable]
 * Returns 0 on success, negative on error.
 */
int falcon_keccak_s2_coeffs(int16_t *s2, const void *sig, size_t sig_len) {
	const uint8_t *p = (const uint8_t *)sig;
	if (sig_len < 42) return -1;
	if ((p[0] & 0xF0) != 0x30) return -2; /* Falcon compressed header prefix */
	unsigned logn = p[0] & 0x0F;
	size_t consumed = Zf(comp_decode)(s2, logn, p + 41, sig_len - 41);
	return consumed > 0 ? 0 : -3;
}

/*
 * Copy the 40-byte nonce from a Keccak-mode compressed signature into nonce[].
 * Returns 0 on success, negative on error.
 */
int falcon_keccak_nonce(uint8_t *nonce, const void *sig, size_t sig_len) {
	const uint8_t *p = (const uint8_t *)sig;
	if (sig_len < 41) return -1;
	memcpy(nonce, p + 1, 40);
	return 0;
}
