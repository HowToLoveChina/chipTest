#ifndef _SORT_VERIFY_H_
#define _SORT_VERIFY_H_

struct validData
{
	int n;
	int k;
	blake2b_state *digest;
};

void expandArray(const unsigned char *in, const size_t in_len,
	unsigned char *out, const size_t out_len,
	const size_t bit_len, const size_t byte_pad);
void digestInit(blake2b_state *S, const int n, const int k);
int sortValidator(void *data, const unsigned char *soln);

#endif
