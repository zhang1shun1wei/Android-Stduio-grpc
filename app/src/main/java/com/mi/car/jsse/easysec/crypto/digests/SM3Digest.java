package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.util.Memoable;
import com.mi.car.jsse.easysec.util.Pack;

public class SM3Digest extends GeneralDigest {
    private static final int BLOCK_SIZE = 16;
    private static final int DIGEST_LENGTH = 32;
    private static final int[] T = new int[64];
    private int[] V;
    private int[] W;
    private int[] inwords;
    private int xOff;

    static {
        for (int i = 0; i < 16; i++) {
            T[i] = (2043430169 << i) | (2043430169 >>> (32 - i));
        }
        for (int i2 = 16; i2 < 64; i2++) {
            int n = i2 % 32;
            T[i2] = (2055708042 << n) | (2055708042 >>> (32 - n));
        }
    }

    public SM3Digest() {
        this.V = new int[8];
        this.inwords = new int[16];
        this.W = new int[68];
        reset();
    }

    public SM3Digest(SM3Digest t) {
        super(t);
        this.V = new int[8];
        this.inwords = new int[16];
        this.W = new int[68];
        copyIn(t);
    }

    private void copyIn(SM3Digest t) {
        System.arraycopy(t.V, 0, this.V, 0, this.V.length);
        System.arraycopy(t.inwords, 0, this.inwords, 0, this.inwords.length);
        this.xOff = t.xOff;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "SM3";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return 32;
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public Memoable copy() {
        return new SM3Digest(this);
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public void reset(Memoable other) {
        SM3Digest d = (SM3Digest) other;
        super.copyIn((GeneralDigest) d);
        copyIn(d);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest, com.mi.car.jsse.easysec.crypto.digests.GeneralDigest
    public void reset() {
        super.reset();
        this.V[0] = 1937774191;
        this.V[1] = 1226093241;
        this.V[2] = 388252375;
        this.V[3] = -628488704;
        this.V[4] = -1452330820;
        this.V[5] = 372324522;
        this.V[6] = -477237683;
        this.V[7] = -1325724082;
        this.xOff = 0;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) {
        finish();
        Pack.intToBigEndian(this.V, out, outOff);
        reset();
        return 32;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.digests.GeneralDigest
    public void processWord(byte[] in, int inOff) {
        int inOff2 = inOff + 1;
        int inOff3 = inOff2 + 1;
        this.inwords[this.xOff] = ((in[inOff] & 255) << 24) | ((in[inOff2] & 255) << 16) | ((in[inOff3] & 255) << 8) | (in[inOff3 + 1] & 255);
        this.xOff++;
        if (this.xOff >= 16) {
            processBlock();
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.digests.GeneralDigest
    public void processLength(long bitLength) {
        if (this.xOff > 14) {
            this.inwords[this.xOff] = 0;
            this.xOff++;
            processBlock();
        }
        while (this.xOff < 14) {
            this.inwords[this.xOff] = 0;
            this.xOff++;
        }
        int[] iArr = this.inwords;
        int i = this.xOff;
        this.xOff = i + 1;
        iArr[i] = (int) (bitLength >>> 32);
        int[] iArr2 = this.inwords;
        int i2 = this.xOff;
        this.xOff = i2 + 1;
        iArr2[i2] = (int) bitLength;
    }

    private int P0(int x) {
        return (x ^ ((x << 9) | (x >>> 23))) ^ ((x << 17) | (x >>> 15));
    }

    private int P1(int x) {
        return (x ^ ((x << 15) | (x >>> 17))) ^ ((x << 23) | (x >>> 9));
    }

    private int FF0(int x, int y, int z) {
        return (x ^ y) ^ z;
    }

    private int FF1(int x, int y, int z) {
        return (x & y) | (x & z) | (y & z);
    }

    private int GG0(int x, int y, int z) {
        return (x ^ y) ^ z;
    }

    private int GG1(int x, int y, int z) {
        return (x & y) | ((x ^ -1) & z);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.digests.GeneralDigest
    public void processBlock() {
        for (int j = 0; j < 16; j++) {
            this.W[j] = this.inwords[j];
        }
        for (int j2 = 16; j2 < 68; j2++) {
            int wj3 = this.W[j2 - 3];
            int wj13 = this.W[j2 - 13];
            int r7 = (wj13 << 7) | (wj13 >>> 25);
            this.W[j2] = (P1((this.W[j2 - 16] ^ this.W[j2 - 9]) ^ ((wj3 << 15) | (wj3 >>> 17))) ^ r7) ^ this.W[j2 - 6];
        }
        int A = this.V[0];
        int B = this.V[1];
        int C = this.V[2];
        int D = this.V[3];
        int E = this.V[4];
        int F = this.V[5];
        int G = this.V[6];
        int H = this.V[7];
        for (int j3 = 0; j3 < 16; j3++) {
            int a12 = (A << 12) | (A >>> 20);
            int s1_ = a12 + E + T[j3];
            int SS1 = (s1_ << 7) | (s1_ >>> 25);
            int Wj = this.W[j3];
            int TT2 = GG0(E, F, G) + H + SS1 + Wj;
            D = C;
            C = (B << 9) | (B >>> 23);
            B = A;
            A = FF0(A, B, C) + D + (SS1 ^ a12) + (Wj ^ this.W[j3 + 4]);
            H = G;
            G = (F << 19) | (F >>> 13);
            F = E;
            E = P0(TT2);
        }
        for (int j4 = 16; j4 < 64; j4++) {
            int a122 = (A << 12) | (A >>> 20);
            int s1_2 = a122 + E + T[j4];
            int SS12 = (s1_2 << 7) | (s1_2 >>> 25);
            int Wj2 = this.W[j4];
            int TT22 = GG1(E, F, G) + H + SS12 + Wj2;
            D = C;
            C = (B << 9) | (B >>> 23);
            B = A;
            A = FF1(A, B, C) + D + (SS12 ^ a122) + (Wj2 ^ this.W[j4 + 4]);
            H = G;
            G = (F << 19) | (F >>> 13);
            F = E;
            E = P0(TT22);
        }
        int[] iArr = this.V;
        iArr[0] = iArr[0] ^ A;
        int[] iArr2 = this.V;
        iArr2[1] = iArr2[1] ^ B;
        int[] iArr3 = this.V;
        iArr3[2] = iArr3[2] ^ C;
        int[] iArr4 = this.V;
        iArr4[3] = iArr4[3] ^ D;
        int[] iArr5 = this.V;
        iArr5[4] = iArr5[4] ^ E;
        int[] iArr6 = this.V;
        iArr6[5] = iArr6[5] ^ F;
        int[] iArr7 = this.V;
        iArr7[6] = iArr7[6] ^ G;
        int[] iArr8 = this.V;
        iArr8[7] = iArr8[7] ^ H;
        this.xOff = 0;
    }
}
