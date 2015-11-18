#include "rijndael.h"

void rijndaelDecrypt(const u32 *rk, int nrounds, const u8 ciphertext[16],
		u8 plaintext[16]) {
	u32 s0, s1, s2, s3, t0, t1, t2, t3;
#ifndef FULL_UNROLL
	int r;
#endif /* ?FULL_UNROLL */

	/*
	 * map byte array block to cipher state
	 * and add initial round key:
	 */
	s0 = GETU32(ciphertext) ^ rk[0];
	s1 = GETU32(ciphertext + 4) ^ rk[1];
	s2 = GETU32(ciphertext + 8) ^ rk[2];
	s3 = GETU32(ciphertext + 12) ^ rk[3];
#ifdef FULL_UNROLL
	/* round 1: */
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^
		Td3[s1 & 0xff] ^ rk[4];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^
		Td3[s2 & 0xff] ^ rk[5];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^
		Td3[s3 & 0xff] ^ rk[6];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^
		Td3[s0 & 0xff] ^ rk[7];
	/* round 2: */
	s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^
		Td3[t1 & 0xff] ^ rk[8];
	s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^
		Td3[t2 & 0xff] ^ rk[9];
	s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^
		Td3[t3 & 0xff] ^ rk[10];
	s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^
		Td3[t0 & 0xff] ^ rk[11];
	/* round 3: */
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^
		Td3[s1 & 0xff] ^ rk[12];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^
		Td3[s2 & 0xff] ^ rk[13];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^
		Td3[s3 & 0xff] ^ rk[14];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^
		Td3[s0 & 0xff] ^ rk[15];
	/* round 4: */
	s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^
		Td3[t1 & 0xff] ^ rk[16];
	s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^
		Td3[t2 & 0xff] ^ rk[17];
	s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^
		Td3[t3 & 0xff] ^ rk[18];
	s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^
		Td3[t0 & 0xff] ^ rk[19];
	/* round 5: */
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^
		Td3[s1 & 0xff] ^ rk[20];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^
		Td3[s2 & 0xff] ^ rk[21];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^
		Td3[s3 & 0xff] ^ rk[22];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^
		Td3[s0 & 0xff] ^ rk[23];
	/* round 6: */
	s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^
		Td3[t1 & 0xff] ^ rk[24];
	s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^
		Td3[t2 & 0xff] ^ rk[25];
	s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^
		Td3[t3 & 0xff] ^ rk[26];
	s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^
		Td3[t0 & 0xff] ^ rk[27];
	/* round 7: */
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^
		Td3[s1 & 0xff] ^ rk[28];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^
		Td3[s2 & 0xff] ^ rk[29];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^
		Td3[s3 & 0xff] ^ rk[30];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^
		Td3[s0 & 0xff] ^ rk[31];
	/* round 8: */
	s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^
		Td3[t1 & 0xff] ^ rk[32];
	s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^
		Td3[t2 & 0xff] ^ rk[33];
	s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^
		Td3[t3 & 0xff] ^ rk[34];
	s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^
		Td3[t0 & 0xff] ^ rk[35];
	/* round 9: */
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^
		Td3[s1 & 0xff] ^ rk[36];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^
		Td3[s2 & 0xff] ^ rk[37];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^
		Td3[s3 & 0xff] ^ rk[38];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^
		Td3[s0 & 0xff] ^ rk[39];
	if (nrounds > 10) {
		/* round 10: */
		s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^
			Td3[t1 & 0xff] ^ rk[40];
		s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^
			Td3[t2 & 0xff] ^ rk[41];
		s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^
			Td3[t3 & 0xff] ^ rk[42];
		s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^
			Td3[t0 & 0xff] ^ rk[43];
		/* round 11: */
		t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^
			Td3[s1 & 0xff] ^ rk[44];
		t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^
			Td3[s2 & 0xff] ^ rk[45];
		t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^
			Td3[s3 & 0xff] ^ rk[46];
		t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^
			Td3[s0 & 0xff] ^ rk[47];
		if (nrounds > 12) {
			/* round 12: */
			s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^
				Td3[t1 & 0xff] ^ rk[48];
			s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^
				Td3[t2 & 0xff] ^ rk[49];
			s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^
				Td3[t3 & 0xff] ^ rk[50];
			s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^
				Td3[t0 & 0xff] ^ rk[51];
			/* round 13: */
			t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^
				Td3[s1 & 0xff] ^ rk[52];
			t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^
				Td3[s2 & 0xff] ^ rk[53];
			t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^
				Td3[s3 & 0xff] ^ rk[54];
			t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^
				Td3[s0 & 0xff] ^ rk[55];
		}
	}
	rk += nrounds << 2;
#else /* !FULL_UNROLL */
	/*
	 * nrounds - 1 full rounds:
	 */
	r = nrounds >> 1;
	for (;;) {
		t0 = Td0[(s0 >> 24)] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^
			Td3[(s1) & 0xff] ^ rk[4];
		t1 = Td0[(s1 >> 24)] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^
			Td3[(s2) & 0xff] ^ rk[5];
		t2 = Td0[(s2 >> 24)] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^
			Td3[(s3) & 0xff] ^ rk[6];
		t3 = Td0[(s3 >> 24)] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^
			Td3[(s0) & 0xff] ^ rk[7];
		rk += 8;
		if (--r == 0)
			break;
		s0 = Td0[(t0 >> 24)] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^
			Td3[(t1) & 0xff] ^ rk[0];
		s1 = Td0[(t1 >> 24)] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^
			Td3[(t2) & 0xff] ^ rk[1];
		s2 = Td0[(t2 >> 24)] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^
			Td3[(t3) & 0xff] ^ rk[2];
		s3 = Td0[(t3 >> 24)] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^
			Td3[(t0) & 0xff] ^ rk[3];
	}
#endif /* ?FULL_UNROLL */
	/*
	 * apply last round and
	 * map cipher state to byte array block:
	 */
	s0 = (Td4[(t0 >> 24)] & 0xff000000) ^ (Td4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
		(Td4[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Td4[(t1) & 0xff] & 0x000000ff) ^
		rk[0];
	PUTU32(plaintext, s0);
	s1 = (Td4[(t1 >> 24)] & 0xff000000) ^ (Td4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
		(Td4[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Td4[(t2) & 0xff] & 0x000000ff) ^
		rk[1];
	PUTU32(plaintext + 4, s1);
	s2 = (Td4[(t2 >> 24)] & 0xff000000) ^ (Td4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
		(Td4[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Td4[(t3) & 0xff] & 0x000000ff) ^
		rk[2];
	PUTU32(plaintext + 8, s2);
	s3 = (Td4[(t3 >> 24)] & 0xff000000) ^ (Td4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
		(Td4[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Td4[(t0) & 0xff] & 0x000000ff) ^
		rk[3];
	PUTU32(plaintext + 12, s3);
}

/**
 * Expand the cipher key into the decryption key schedule.
 *
 * @return the number of rounds for the given cipher key size.
 */
int rijndaelSetupDecrypt(u32 *rk, const u8 *key, int keybits) {
	int nrounds, i, j;
	u32 temp;

	/* expand the cipher key: */
	nrounds = rijndaelSetupEncrypt(rk, key, keybits);
	/* invert the order of the round keys: */
	for (i = 0, j = 4 *nrounds; i < j; i += 4, j -= 4) {
		temp = rk[i];
		rk[i] = rk[j];
		rk[j] = temp;
		temp = rk[i + 1];
		rk[i + 1] = rk[j + 1];
		rk[j + 1] = temp;
		temp = rk[i + 2];
		rk[i + 2] = rk[j + 2];
		rk[j + 2] = temp;
		temp = rk[i + 3];
		rk[i + 3] = rk[j + 3];
		rk[j + 3] = temp;
	}
	/* apply the inverse MixColumn transform to all round keys but the first and
	 * the last: */
	for (i = 1; i < nrounds; i++) {
		rk += 4;
		rk[0] =
			Td0[Te4[(rk[0] >> 24)] & 0xff] ^ Td1[Te4[(rk[0] >> 16) & 0xff] & 0xff] ^
			Td2[Te4[(rk[0] >> 8) & 0xff] & 0xff] ^ Td3[Te4[(rk[0]) & 0xff] & 0xff];
		rk[1] =
			Td0[Te4[(rk[1] >> 24)] & 0xff] ^ Td1[Te4[(rk[1] >> 16) & 0xff] & 0xff] ^
			Td2[Te4[(rk[1] >> 8) & 0xff] & 0xff] ^ Td3[Te4[(rk[1]) & 0xff] & 0xff];
		rk[2] =
			Td0[Te4[(rk[2] >> 24)] & 0xff] ^ Td1[Te4[(rk[2] >> 16) & 0xff] & 0xff] ^
			Td2[Te4[(rk[2] >> 8) & 0xff] & 0xff] ^ Td3[Te4[(rk[2]) & 0xff] & 0xff];
		rk[3] =
			Td0[Te4[(rk[3] >> 24)] & 0xff] ^ Td1[Te4[(rk[3] >> 16) & 0xff] & 0xff] ^
			Td2[Te4[(rk[3] >> 8) & 0xff] & 0xff] ^ Td3[Te4[(rk[3]) & 0xff] & 0xff];
	}
	return nrounds;
}

/**
 * Expand the cipher key into the encryption key schedule.
 *
 * @return the number of rounds for the given cipher key size.
 */
int rijndaelSetupEncrypt(u32 *rk, const u8 *key, int keybits) {
	int i = 0;
	u32 temp;

	rk[0] = GETU32(key);
	rk[1] = GETU32(key + 4);
	rk[2] = GETU32(key + 8);
	rk[3] = GETU32(key + 12);
	if (keybits == 128) {
		for (;;) {
			temp = rk[3];
			rk[4] = rk[0] ^ (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te4[(temp >> 8) & 0xff] & 0x00ff0000) ^
				(Te4[(temp) & 0xff] & 0x0000ff00) ^
				(Te4[(temp >> 24)] & 0x000000ff) ^ rcon[i];
			rk[5] = rk[1] ^ rk[4];
			rk[6] = rk[2] ^ rk[5];
			rk[7] = rk[3] ^ rk[6];
			if (++i == 10)
				return 10;
			rk += 4;
		}
	}
	rk[4] = GETU32(key + 16);
	rk[5] = GETU32(key + 20);
	if (keybits == 192) {
		for (;;) {
			temp = rk[5];
			rk[6] = rk[0] ^ (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te4[(temp >> 8) & 0xff] & 0x00ff0000) ^
				(Te4[(temp) & 0xff] & 0x0000ff00) ^
				(Te4[(temp >> 24)] & 0x000000ff) ^ rcon[i];
			rk[7] = rk[1] ^ rk[6];
			rk[8] = rk[2] ^ rk[7];
			rk[9] = rk[3] ^ rk[8];
			if (++i == 8)
				return 12;
			rk[10] = rk[4] ^ rk[9];
			rk[11] = rk[5] ^ rk[10];
			rk += 6;
		}
	}
	rk[6] = GETU32(key + 24);
	rk[7] = GETU32(key + 28);
	if (keybits == 256) {
		for (;;) {
			temp = rk[7];
			rk[8] = rk[0] ^ (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te4[(temp >> 8) & 0xff] & 0x00ff0000) ^
				(Te4[(temp) & 0xff] & 0x0000ff00) ^
				(Te4[(temp >> 24)] & 0x000000ff) ^ rcon[i];
			rk[9] = rk[1] ^ rk[8];
			rk[10] = rk[2] ^ rk[9];
			rk[11] = rk[3] ^ rk[10];
			if (++i == 7)
				return 14;
			temp = rk[11];
			rk[12] = rk[4] ^ (Te4[(temp >> 24)] & 0xff000000) ^
				(Te4[(temp >> 16) & 0xff] & 0x00ff0000) ^
				(Te4[(temp >> 8) & 0xff] & 0x0000ff00) ^
				(Te4[(temp) & 0xff] & 0x000000ff);
			rk[13] = rk[5] ^ rk[12];
			rk[14] = rk[6] ^ rk[13];
			rk[15] = rk[7] ^ rk[14];
			rk += 8;
		}
	}
	return 0;
}
