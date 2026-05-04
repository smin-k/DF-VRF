#include "inner.h"

/* Expose the forward NTT (mod q, no Montgomery) for Go bindings. */
void falcon_ntt_forward(uint16_t *h, unsigned logn) {
	Zf(mq_NTT)(h, logn);
}
