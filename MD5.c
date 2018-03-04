#include <memory.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

unsigned char PADDING[] = {
	128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

unsigned int F(unsigned int A, unsigned int B, unsigned int C, unsigned int D, unsigned int X, unsigned int T, unsigned int S) {
	A += ((B & C) | (~B & D));
	A += X + T;
	A = ((A << S) | (A >> (32 - S)));
	A += B;
	return A;
}

unsigned int G(unsigned int A, unsigned int B, unsigned int C, unsigned int D, unsigned int X, unsigned int T, unsigned int S) {
	A += ((B & D) | (C & ~D));
	A += X + T;
	A = ((A << S) | (A >> (32 - S)));
	A += B;
	return A;
}

unsigned int H(unsigned int A, unsigned int B, unsigned int C, unsigned int D, unsigned int X, unsigned int T, unsigned int S) {
	A += (B ^ C ^ D);
	A += X + T;
	A = ((A << S) | (A >> (32 - S)));
	A += B;
	return A;
}

unsigned int I(unsigned int A, unsigned int B, unsigned int C, unsigned int D, unsigned int X, unsigned int T, unsigned int S) {
	A += (C ^ (B | ~D));
	A += X + T;
	A = ((A << S) | (A >> (32 - S)));
	A += B;
	return A;
}

void H_MD5(unsigned int CV[4], unsigned char input[64]) {
	unsigned int a = CV[0];
	unsigned int b = CV[1];
	unsigned int c = CV[2];
	unsigned int d = CV[3];
	
	int S[64] = {
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	};
	unsigned int *  indexes = (unsigned int *)input;
	unsigned int X[64] = {
		0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
		1, 6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
		5, 8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
		0, 7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9
	};
	int i;
	for (i = 0; i < 16; i++) {
		unsigned int T = pow(2, 32) * fabs(sin(i + 1));//printf("T:%x s:%d x:%d\n", T, S[i], X[i]);
		a = F(a, b, c, d, indexes[X[i]], T, S[i]);
		int tmp = d;
		d = c;
		c = b;
		b = a;
		a = tmp;
	}
	for (i = 16; i < 32; i++) {
		unsigned int T = pow(2, 32) * fabs(sin(i + 1));//printf("T:%x s:%d x:%d\n", T, S[i], X[i]);
		a = G(a, b, c, d, indexes[X[i]], T, S[i]);
		int tmp = d;
		d = c;
		c = b;
		b = a;
		a = tmp;
	}
	for (i = 32; i < 48; i++) {
		unsigned int T = pow(2, 32) * fabs(sin(i + 1));//printf("T:%x s:%d x:%d\n", T, S[i], X[i]);
		a = H(a, b, c, d, indexes[X[i]], T, S[i]);
		int tmp = d;
		d = c;
		c = b;
		b = a;
		a = tmp;
	}
	for (i = 48; i < 64; i++) {
		unsigned int T = pow(2, 32) * fabs(sin(i + 1));//printf("T:%x s:%d x:%d\n", T, S[i], X[i]);
		a = I(a, b, c, d, indexes[X[i]], T, S[i]);
		int tmp = d;
		d = c;
		c = b;
		b = a;
		a = tmp;
	}
	CV[0] += a;
	CV[1] += b;
	CV[2] += c;
	CV[3] += d;
}

void MD5(unsigned char * cypher, unsigned char * plain) {
	unsigned int CV[4];
	unsigned int Buffer[16];
	CV[0] = 0x67452301;
	CV[1] = 0xEFCDAB89;
	CV[2] = 0x98BADCFE;
	CV[3] = 0x10325476;
	int i = 0;
	for (i = 0; i + 64 <= strlen(plain); i += 64) {
		H_MD5(CV, plain + i);
	}
	int end = i;
	memcpy((unsigned char*)Buffer, plain + end, strlen(plain) - end);

	if (strlen(plain) - end < 56) {
		memcpy((unsigned char*)Buffer + strlen(plain) - end, PADDING, 56 - (strlen(plain) - end));
	} else {
		memcpy((unsigned char*)Buffer + strlen(plain) - end, PADDING, 64 - (strlen(plain) - end));
		H_MD5(CV, (unsigned char *)Buffer);
		memcpy((unsigned char*)Buffer, PADDING + 8, 56);
	}
	unsigned long long length = strlen(plain) << 3;
	memcpy((unsigned char*)Buffer + 56, &length, 8);
	H_MD5(CV, (unsigned char *)Buffer);

	unsigned char * tmp = (unsigned char *)CV;
	for (i = 0; i < 16; i++) {
		cypher[i] = tmp[i];
	}
}

int main(int argc, char *argv[]) {
	unsigned char plain[] ="I'm Jack!";
	unsigned char cypher[16];//1137e3b1c91cc53d0886da77f2993a2d
	
	MD5(cypher, plain);
	printf("Plain  Text: %s\n", plain);
	printf("Cypher Text: ");
	int i;
	for(i = 0; i < 16; i++) {
		printf("%02x", cypher[i]);
	}
	return 0;
}
