package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.asn1.x509.DisplayText;
import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.math.Primes;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Memoable;

public final class WhirlpoolDigest implements ExtendedDigest, Memoable {
    private static final int BITCOUNT_ARRAY_SIZE = 32;
    private static final int BYTE_LENGTH = 64;
    private static final long[] C0 = new long[256];
    private static final long[] C1 = new long[256];
    private static final long[] C2 = new long[256];
    private static final long[] C3 = new long[256];
    private static final long[] C4 = new long[256];
    private static final long[] C5 = new long[256];
    private static final long[] C6 = new long[256];
    private static final long[] C7 = new long[256];
    private static final int DIGEST_LENGTH_BYTES = 64;
    private static final short[] EIGHT = new short[32];
    private static final int REDUCTION_POLYNOMIAL = 285;
    private static final int ROUNDS = 10;
    private static final int[] SBOX = {24, 35, 198, 232, 135, 184, 1, 79, 54, 166, 210, 245, 121, 111, 145, 82, 96, 188, 155, 142, 163, 12, 123, 53, 29, BERTags.FLAGS, 215, 194, 46, 75, 254, 87, 21, 119, 55, 229, 159, 240, 74, 218, 88, 201, 41, 10, 177, 160, 107, 133, 189, 93, 16, 244, 203, 62, 5, 103, 228, 39, 65, 139, 167, 125, 149, 216, 251, 238, 124, 102, 221, 23, 71, 158, 202, 45, 191, 7, 173, 90, 131, 51, 99, 2, 170, 113, DisplayText.DISPLAY_TEXT_MAXIMUM_SIZE, 25, 73, 217, 242, 227, 91, 136, 154, 38, 50, 176, 233, 15, 213, 128, 190, 205, 52, 72, GF2Field.MASK, 122, 144, 95, 32, 104, 26, 174, 180, 84, 147, 34, 100, 241, 115, 18, 64, 8, 195, 236, 219, 161, 141, 61, 151, 0, 207, 43, 118, 130, 214, 27, 181, 175, 106, 80, 69, 243, 48, 239, 63, 85, 162, 234, 101, 186, 47, BERTags.PRIVATE, 222, 28, 253, 77, 146, 117, 6, 138, 178, 230, 14, 31, 98, 212, 168, 150, 249, 197, 37, 89, 132, 114, 57, 76, 94, 120, 56, 140, 209, 165, 226, 97, 179, 33, 156, 30, 67, 199, 252, 4, 81, 153, 109, 13, 250, 223, 126, 36, 59, 171, 206, 17, 143, 78, 183, 235, 60, 129, 148, 247, 185, 19, 44, Primes.SMALL_FACTOR_LIMIT, 231, 110, 196, 3, 86, 68, 127, 169, 42, 187, 193, 83, 220, 11, 157, 108, 49, 116, 246, 70, 172, 137, 20, 225, 22, 58, 105, 9, 112, 182, 208, 237, 204, 66, 152, 164, 40, 92, 248, 134};
    private long[] _K;
    private long[] _L;
    private short[] _bitCount;
    private long[] _block;
    private byte[] _buffer;
    private int _bufferPos;
    private long[] _hash;
    private final long[] _rc;
    private long[] _state;

    static {
        EIGHT[31] = 8;
    }

    public WhirlpoolDigest() {
        this._rc = new long[11];
        this._buffer = new byte[64];
        this._bufferPos = 0;
        this._bitCount = new short[32];
        this._hash = new long[8];
        this._K = new long[8];
        this._L = new long[8];
        this._block = new long[8];
        this._state = new long[8];
        for (int i = 0; i < 256; i++) {
            int v1 = SBOX[i];
            int v2 = maskWithReductionPolynomial(v1 << 1);
            int v4 = maskWithReductionPolynomial(v2 << 1);
            int v5 = v4 ^ v1;
            int v8 = maskWithReductionPolynomial(v4 << 1);
            int v9 = v8 ^ v1;
            C0[i] = packIntoLong(v1, v1, v4, v1, v8, v5, v2, v9);
            C1[i] = packIntoLong(v9, v1, v1, v4, v1, v8, v5, v2);
            C2[i] = packIntoLong(v2, v9, v1, v1, v4, v1, v8, v5);
            C3[i] = packIntoLong(v5, v2, v9, v1, v1, v4, v1, v8);
            C4[i] = packIntoLong(v8, v5, v2, v9, v1, v1, v4, v1);
            C5[i] = packIntoLong(v1, v8, v5, v2, v9, v1, v1, v4);
            C6[i] = packIntoLong(v4, v1, v8, v5, v2, v9, v1, v1);
            C7[i] = packIntoLong(v1, v4, v1, v8, v5, v2, v9, v1);
        }
        this._rc[0] = 0;
        for (int r = 1; r <= 10; r++) {
            int i2 = (r - 1) * 8;
            this._rc[r] = (((((((C0[i2] & -72057594037927936L) ^ (C1[i2 + 1] & 71776119061217280L)) ^ (C2[i2 + 2] & 280375465082880L)) ^ (C3[i2 + 3] & 1095216660480L)) ^ (C4[i2 + 4] & 4278190080L)) ^ (C5[i2 + 5] & 16711680)) ^ (C6[i2 + 6] & 65280)) ^ (C7[i2 + 7] & 255);
        }
    }

    private long packIntoLong(int b7, int b6, int b5, int b4, int b3, int b2, int b1, int b0) {
        return (((((((((long) b7) << 56) ^ (((long) b6) << 48)) ^ (((long) b5) << 40)) ^ (((long) b4) << 32)) ^ (((long) b3) << 24)) ^ (((long) b2) << 16)) ^ (((long) b1) << 8)) ^ ((long) b0);
    }

    private int maskWithReductionPolynomial(int input) {
        if (((long) input) >= 256) {
            return input ^ REDUCTION_POLYNOMIAL;
        }
        return input;
    }

    public WhirlpoolDigest(WhirlpoolDigest originalDigest) {
        this._rc = new long[11];
        this._buffer = new byte[64];
        this._bufferPos = 0;
        this._bitCount = new short[32];
        this._hash = new long[8];
        this._K = new long[8];
        this._L = new long[8];
        this._block = new long[8];
        this._state = new long[8];
        reset(originalDigest);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "Whirlpool";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return 64;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) {
        finish();
        for (int i = 0; i < 8; i++) {
            convertLongToByteArray(this._hash[i], out, (i * 8) + outOff);
        }
        reset();
        return getDigestSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this._bufferPos = 0;
        Arrays.fill(this._bitCount, (short) 0);
        Arrays.fill(this._buffer, (byte) 0);
        Arrays.fill(this._hash, 0);
        Arrays.fill(this._K, 0);
        Arrays.fill(this._L, 0);
        Arrays.fill(this._block, 0);
        Arrays.fill(this._state, 0);
    }

    private void processFilledBuffer(byte[] in, int inOff) {
        for (int i = 0; i < this._state.length; i++) {
            this._block[i] = bytesToLongFromBuffer(this._buffer, i * 8);
        }
        processBlock();
        this._bufferPos = 0;
        Arrays.fill(this._buffer, (byte) 0);
    }

    private long bytesToLongFromBuffer(byte[] buffer, int startPos) {
        return ((((long) buffer[startPos + 0]) & 255) << 56) | ((((long) buffer[startPos + 1]) & 255) << 48) | ((((long) buffer[startPos + 2]) & 255) << 40) | ((((long) buffer[startPos + 3]) & 255) << 32) | ((((long) buffer[startPos + 4]) & 255) << 24) | ((((long) buffer[startPos + 5]) & 255) << 16) | ((((long) buffer[startPos + 6]) & 255) << 8) | (((long) buffer[startPos + 7]) & 255);
    }

    private void convertLongToByteArray(long inputLong, byte[] outputArray, int offSet) {
        for (int i = 0; i < 8; i++) {
            outputArray[offSet + i] = (byte) ((int) ((inputLong >> (56 - (i * 8))) & 255));
        }
    }

    /* access modifiers changed from: protected */
    public void processBlock() {
        for (int i = 0; i < 8; i++) {
            long[] jArr = this._state;
            long j = this._block[i];
            long[] jArr2 = this._K;
            long j2 = this._hash[i];
            jArr2[i] = j2;
            jArr[i] = j ^ j2;
        }
        for (int round = 1; round <= 10; round++) {
            for (int i2 = 0; i2 < 8; i2++) {
                this._L[i2] = 0;
                long[] jArr3 = this._L;
                jArr3[i2] = jArr3[i2] ^ C0[((int) (this._K[(i2 + 0) & 7] >>> 56)) & GF2Field.MASK];
                long[] jArr4 = this._L;
                jArr4[i2] = jArr4[i2] ^ C1[((int) (this._K[(i2 - 1) & 7] >>> 48)) & GF2Field.MASK];
                long[] jArr5 = this._L;
                jArr5[i2] = jArr5[i2] ^ C2[((int) (this._K[(i2 - 2) & 7] >>> 40)) & GF2Field.MASK];
                long[] jArr6 = this._L;
                jArr6[i2] = jArr6[i2] ^ C3[((int) (this._K[(i2 - 3) & 7] >>> 32)) & GF2Field.MASK];
                long[] jArr7 = this._L;
                jArr7[i2] = jArr7[i2] ^ C4[((int) (this._K[(i2 - 4) & 7] >>> 24)) & GF2Field.MASK];
                long[] jArr8 = this._L;
                jArr8[i2] = jArr8[i2] ^ C5[((int) (this._K[(i2 - 5) & 7] >>> 16)) & GF2Field.MASK];
                long[] jArr9 = this._L;
                jArr9[i2] = jArr9[i2] ^ C6[((int) (this._K[(i2 - 6) & 7] >>> 8)) & GF2Field.MASK];
                long[] jArr10 = this._L;
                jArr10[i2] = jArr10[i2] ^ C7[((int) this._K[(i2 - 7) & 7]) & GF2Field.MASK];
            }
            System.arraycopy(this._L, 0, this._K, 0, this._K.length);
            long[] jArr11 = this._K;
            jArr11[0] = jArr11[0] ^ this._rc[round];
            for (int i3 = 0; i3 < 8; i3++) {
                this._L[i3] = this._K[i3];
                long[] jArr12 = this._L;
                jArr12[i3] = jArr12[i3] ^ C0[((int) (this._state[(i3 + 0) & 7] >>> 56)) & GF2Field.MASK];
                long[] jArr13 = this._L;
                jArr13[i3] = jArr13[i3] ^ C1[((int) (this._state[(i3 - 1) & 7] >>> 48)) & GF2Field.MASK];
                long[] jArr14 = this._L;
                jArr14[i3] = jArr14[i3] ^ C2[((int) (this._state[(i3 - 2) & 7] >>> 40)) & GF2Field.MASK];
                long[] jArr15 = this._L;
                jArr15[i3] = jArr15[i3] ^ C3[((int) (this._state[(i3 - 3) & 7] >>> 32)) & GF2Field.MASK];
                long[] jArr16 = this._L;
                jArr16[i3] = jArr16[i3] ^ C4[((int) (this._state[(i3 - 4) & 7] >>> 24)) & GF2Field.MASK];
                long[] jArr17 = this._L;
                jArr17[i3] = jArr17[i3] ^ C5[((int) (this._state[(i3 - 5) & 7] >>> 16)) & GF2Field.MASK];
                long[] jArr18 = this._L;
                jArr18[i3] = jArr18[i3] ^ C6[((int) (this._state[(i3 - 6) & 7] >>> 8)) & GF2Field.MASK];
                long[] jArr19 = this._L;
                jArr19[i3] = jArr19[i3] ^ C7[((int) this._state[(i3 - 7) & 7]) & GF2Field.MASK];
            }
            System.arraycopy(this._L, 0, this._state, 0, this._state.length);
        }
        for (int i4 = 0; i4 < 8; i4++) {
            long[] jArr20 = this._hash;
            jArr20[i4] = jArr20[i4] ^ (this._state[i4] ^ this._block[i4]);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) {
        this._buffer[this._bufferPos] = in;
        this._bufferPos++;
        if (this._bufferPos == this._buffer.length) {
            processFilledBuffer(this._buffer, 0);
        }
        increment();
    }

    private void increment() {
        int carry = 0;
        for (int i = this._bitCount.length - 1; i >= 0; i--) {
            int sum = (this._bitCount[i] & 255) + EIGHT[i] + carry;
            carry = sum >>> 8;
            this._bitCount[i] = (short) (sum & GF2Field.MASK);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) {
        while (len > 0) {
            update(in[inOff]);
            inOff++;
            len--;
        }
    }

    private void finish() {
        byte[] bitLength = copyBitLength();
        byte[] bArr = this._buffer;
        int i = this._bufferPos;
        this._bufferPos = i + 1;
        bArr[i] = (byte) (bArr[i] | 128);
        if (this._bufferPos == this._buffer.length) {
            processFilledBuffer(this._buffer, 0);
        }
        if (this._bufferPos > 32) {
            while (this._bufferPos != 0) {
                update((byte) 0);
            }
        }
        while (this._bufferPos <= 32) {
            update((byte) 0);
        }
        System.arraycopy(bitLength, 0, this._buffer, 32, bitLength.length);
        processFilledBuffer(this._buffer, 0);
    }

    private byte[] copyBitLength() {
        byte[] rv = new byte[32];
        for (int i = 0; i < rv.length; i++) {
            rv[i] = (byte) (this._bitCount[i] & 255);
        }
        return rv;
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return 64;
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public Memoable copy() {
        return new WhirlpoolDigest(this);
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public void reset(Memoable other) {
        WhirlpoolDigest originalDigest = (WhirlpoolDigest) other;
        System.arraycopy(originalDigest._rc, 0, this._rc, 0, this._rc.length);
        System.arraycopy(originalDigest._buffer, 0, this._buffer, 0, this._buffer.length);
        this._bufferPos = originalDigest._bufferPos;
        System.arraycopy(originalDigest._bitCount, 0, this._bitCount, 0, this._bitCount.length);
        System.arraycopy(originalDigest._hash, 0, this._hash, 0, this._hash.length);
        System.arraycopy(originalDigest._K, 0, this._K, 0, this._K.length);
        System.arraycopy(originalDigest._L, 0, this._L, 0, this._L.length);
        System.arraycopy(originalDigest._block, 0, this._block, 0, this._block.length);
        System.arraycopy(originalDigest._state, 0, this._state, 0, this._state.length);
    }
}
