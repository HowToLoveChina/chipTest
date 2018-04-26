#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include "sha256.h"
#include "blake2b.h"
#include "sort-verify.h"
#include "util.h"
#include "logging.h"
#include "platform-app.h"
#if defined(__linux__)
#include "endian.h"
#endif

static void compressArray(const unsigned char *in, const size_t in_len,
                          unsigned char *out, const size_t out_len,
                          const size_t bit_len, const size_t byte_pad)
{
    assert(bit_len >= 8);
    assert(8 * sizeof(uint32_t) >= 7 + bit_len);

    const size_t in_width = (bit_len + 7) / 8 + byte_pad;
    assert(out_len == bit_len * in_len / (8 * in_width));

    const uint32_t bit_len_mask = ((uint32_t)1 << bit_len) - 1;

    // The acc_bits least-significant bits of acc_value represent a bit sequence
    // in big-endian order.
    size_t acc_bits = 0;
    uint32_t acc_value = 0;

    size_t j = 0;
    for (size_t i = 0; i < out_len; i++)
    {
        // When we have fewer than 8 bits left in the accumulator, read the next
        // input element.
        if (acc_bits < 8)
        {
            acc_value = acc_value << bit_len;
            for (size_t x = byte_pad; x < in_width; x++)
            {
                acc_value = acc_value | (
                        (
                                // Apply bit_len_mask across byte boundaries
                                in[j + x] & ((bit_len_mask >> (8 * (in_width - x - 1))) & 0xFF)
                        ) << (8 * (in_width - x - 1))); // Big-endian
            }
            j += in_width;
            acc_bits += bit_len;
        }

        acc_bits -= 8;
        out[i] = (acc_value >> acc_bits) & 0xFF;
    }
}

void expandArray(const unsigned char *in, const size_t in_len,
	unsigned char *out, const size_t out_len,
	const size_t bit_len, const size_t byte_pad)
{
	assert(bit_len >= 8);
	assert(8 * sizeof(uint32_t) >= 7 + bit_len);

	const size_t out_width = (bit_len + 7) / 8 + byte_pad;
	assert(out_len == 8 * out_width * in_len / bit_len);

	const uint32_t bit_len_mask = ((uint32_t)1 << bit_len) - 1;

	// The acc_bits least-significant bits of acc_value represent a bit sequence
	// in big-endian order.
	size_t acc_bits = 0;
	uint32_t acc_value = 0;

	size_t j = 0;
	for (size_t i = 0; i < in_len; i++)
	{
		acc_value = (acc_value << 8) | in[i];
		acc_bits += 8;

		// When we have bit_len or more bits in the accumulator, write the next
		// output element.
		if (acc_bits >= bit_len)
		{
			acc_bits -= bit_len;
			for (size_t x = 0; x < byte_pad; x++)
			{
				out[j + x] = 0;
			}
			for (size_t x = byte_pad; x < out_width; x++)
			{
				out[j + x] = (
					// Big-endian
					acc_value >> (acc_bits + (8 * (out_width - x - 1)))
					) & (
					// Apply bit_len_mask across byte boundaries
					(bit_len_mask >> (8 * (out_width - x - 1))) & 0xFF
					);
			}
			j += out_width;
		}
	}
}

static int getIndices(const uint8_t *hash, size_t len, size_t lenIndices, size_t cBitLen,
                      uint8_t *data, size_t maxLen)
{
    assert(((cBitLen + 1) + 7) / 8 <= sizeof(uint32_t));
    size_t minLen = (cBitLen + 1) * lenIndices / (8 * sizeof(uint32_t));
    size_t bytePad = sizeof(uint32_t) - ((cBitLen + 1 ) + 7 ) / 8;
    if (minLen > maxLen)
        return -1;
    if (data)
        compressArray(hash + len, lenIndices, data, minLen, cBitLen + 1, bytePad);
    return minLen;
}
static int isZero(const uint8_t *hash, size_t len)
{
	// This doesn't need to be constant time.
	for (size_t i = 0; i < len; i++)
	{
		if (hash[i] != 0)
			return 0;
	}
	return 1;
}

static void generateHash(blake2b_state *S, const uint32_t g, uint8_t *hash, const size_t hashLen)
{
	const uint32_t le_g = htole32(g);
	blake2b_state digest = *S; /* copy */

	blake2b_update(&digest, (uint8_t *)&le_g, sizeof(le_g));
	blake2b_final(&digest, hash, hashLen);
}
int compare_size = 3;
static int compareSR(const void *p1, const void *p2)
{
    return memcmp(p1, p2, compare_size) ;
}

#if 0
static void joinSortedArrays(uint32_t *dst, const uint32_t *a, const uint32_t *b, const size_t len)
{
    int i = len - 1, j = len - 1, k = len * 2;

    while (k > 0)
        dst[--k] = (j < 0 || (i >= 0 && a[i] >= b[j]))? a[i--] : b[j--];
}

static void combineRows(uint8_t *hash, const uint8_t *a, const uint8_t *b,
                        const size_t len, const size_t lenIndices, const int trim)
{
    for (size_t i = trim; i < len; i++)
        hash[i - trim] = a[i] ^ b[i];

    joinSortedArrays((uint32_t *)(hash + len - trim),
                     (uint32_t *)(a + len), (uint32_t *)(b + len),
                     lenIndices / sizeof(uint32_t));
}
#endif

void sort_pair(uint32_t *a, uint32_t len)
{
    uint32_t    *b = a + len;
    uint32_t     tmp, need_sorting = 0;

    for (uint32_t i = 0; i < len; i++)
        if (need_sorting || a[i] > b[i])
        {
            need_sorting = 1;
            tmp = a[i];
            a[i] = b[i];
            b[i] = tmp;
        }
        else if (a[i] < b[i])
            return ;
}
#define swap(a, b) \
    do { __typeof__(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)


int sortValidator(void *data, const unsigned char *soln)
{
    const struct validData *v = data;
    const int n = v->n;
    const int k = v->k;
    blake2b_state *digest = v->digest;
    const int collisionBitLength = n / (k + 1);
    const int collisionByteLength = (collisionBitLength + 7) / 8;
    uint32_t hashLength = (k + 1) * collisionByteLength;
    const int indicesPerHashOutput = 512 / n;
    const int hashOutput = indicesPerHashOutput * n / 8;
    const int equihashSolutionSize = (1 << k) * (n / (k + 1) + 1) / 8;
    const int solnr = 1 << 9;
    uint32_t indicesLen = 4;
    uint32_t indices[512];
    uint32_t x_size = 512;
    int err_type = 0;
    compare_size =3;

    expandArray(soln, equihashSolutionSize, (unsigned char *)&indices, sizeof(indices), collisionBitLength + 1, 1);

    uint8_t vHash[30];
    memset(vHash, 0, sizeof(vHash));
    uint8_t *x = malloc(34 * 512);
    uint8_t *xc = malloc(34 * 512);

#define X(y)  (x  + (hashLength                       + indicesLen)     * (y))
#define Xc(y) (xc + (hashLength                       + indicesLen*2)     * (y))

    char * hex_buff = NULL;
    uint32_t xc_size = 0;
    uint8_t tmp_hash[30] = { 0 };

// index去重
    for (int i=0; i < solnr; i++)
    {
        for (int j=i+1; j < solnr; j++)
        {
            if (indices[i] == indices[j]) {
                applog(LOG_ERR, "error: dup index\n");
                platform_get_app()->err_counts.dup_error++;
                err_type = 1;
                goto failed;
            }
        }
    }

//基于index得到value
    for (int j = 0; j < solnr; j++)
    {
        uint8_t tmpHash[50];
        uint8_t hash[30];
        int i = be32toh(indices[j]);

        generateHash(digest, i / indicesPerHashOutput, tmpHash, hashOutput);
        expandArray(tmpHash + (i % indicesPerHashOutput * n / 8), n / 8, hash, hashLength, collisionBitLength, 0);

        for (uint32_t k = 0; k < hashLength; ++k)
            vHash[k] ^= hash[k];

        memcpy(x+j*(hashLength + indicesLen),hash,hashLength);
        memcpy(x+j*(hashLength + indicesLen)+hashLength,(uint8_t *)&(indices[j]),indicesLen);
    }
    if (0 == isZero(vHash, sizeof(vHash))) {
        platform_get_app()->err_counts.xor_error++;
        applog(LOG_ERR, "error: %s xor vHash = 0\n", __func__);
        err_type = 2;
        goto failed;
    }
    memset(vHash, 0, sizeof(vHash));
//排序
    for(int i = 0; i < 9; i++)
    {
        qsort(x, x_size, (hashLength + indicesLen), compareSR);
        xc_size = 0;
        for(size_t j = 0; j < x_size; j+=2)
        {
            for(uint32_t index = 0; index < hashLength; index++ )
                tmp_hash[index] = X(j)[index] ^ X(j+1)[index];
            memcpy(Xc(j/2), tmp_hash, hashLength);
            memcpy(Xc(j/2) + hashLength, X(j)+hashLength, indicesLen);
            memcpy(Xc(j/2) + hashLength + indicesLen, X(j+1)+hashLength, indicesLen);
            xc_size++;
        }

        indicesLen *= 2;
        swap(x,xc);
        x_size = xc_size;
        compare_size += 3;
    }

    uint32_t real_indices[512];
    for(int i =0; i < 512 ; i++)
        real_indices[i] = be32toh(*(uint32_t *)(X(0) + hashLength + i * 4));


    for (uint32_t level = 0; level < 9; level++)
        for (int i = 0; i < (1 << 9); i += (2 << level))
            sort_pair(&real_indices[i], 1 << level);

    indicesLen = 4;
    x_size = 512;

//验证结果
    for (int j = 0; j < solnr; j++)
    {
        uint8_t tmpHash[50];
        uint8_t hash[30];
        int i = real_indices[j];
        generateHash(digest, i / indicesPerHashOutput, tmpHash, hashOutput);
        expandArray(tmpHash + (i % indicesPerHashOutput * n / 8), n / 8, hash, hashLength, collisionBitLength, 0);
        i = be32toh(real_indices[j]);
        memcpy(x+j*(hashLength + indicesLen),hash,hashLength);
        memcpy(x+j*(hashLength + indicesLen)+hashLength,(uint8_t *)&(i),indicesLen);
        hex_buff = bin2hex(X(j),34);
        free(hex_buff);
    }

    for(int i = 0; i < 9; i++)
    {
        //qsort(x, x_size, (hashLength + indicesLen), compareSR);
        xc_size = 0;
        for(uint32_t j = 0; j < x_size; j+=2)
        {
            for(uint32_t index = 0; index < hashLength; index++ )
                tmp_hash[index] = X(j)[index] ^ X(j+1)[index];
            memcpy(Xc(j/2), tmp_hash, hashLength);
            memcpy(Xc(j/2) + hashLength, X(j)+hashLength, indicesLen);
            memcpy(Xc(j/2) + hashLength + indicesLen, X(j+1)+hashLength, indicesLen);
            xc_size++;
        }

        indicesLen *= 2;
        swap(x,xc);
        x_size = xc_size;
        compare_size +=3;
    }
    uint8_t tmp_data[1344];
    getIndices(X(0), hashLength, 512*4, 20, tmp_data, sizeof(tmp_data));
    hex_buff = bin2hex(tmp_data,1344);
    free(hex_buff);

    hex_buff = bin2hex(X(0),hashLength + indicesLen);
    free(hex_buff);
    memcpy(vHash, X(0), 30);
    if (isZero(vHash, sizeof(vHash)) == 0) {
        applog(LOG_ERR, "error: %s valid falied\n", __func__);
        err_type = 3;
    }
failed:
    free(x);
    free(xc);

    return err_type;
}

static void zcashPerson(uint8_t *person, const int n, const int k)
{
    memcpy(person, "ZcashPoW", 8);
    *(uint32_t *)(person +  8) = htole32(n);
    *(uint32_t *)(person + 12) = htole32(k);
}

void digestInit(blake2b_state *S, const int n, const int k)
{
    blake2b_param P[1];

    memset(P, 0, sizeof(blake2b_param));
    P->fanout        = 1;
    P->depth         = 1;
    P->digest_length = (512 / n) * n / 8;
    zcashPerson(P->personal, n, k);
    blake2b_init_param(S, P);
}
