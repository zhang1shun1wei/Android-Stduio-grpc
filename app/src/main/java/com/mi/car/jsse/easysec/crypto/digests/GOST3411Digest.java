package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.crypto.engines.GOST28147Engine;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithSBox;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Memoable;
import com.mi.car.jsse.easysec.util.Pack;
import java.lang.reflect.Array;

public class GOST3411Digest implements ExtendedDigest, Memoable {
    private static final byte[] C2 = {0, -1, 0, -1, 0, -1, 0, -1, -1, 0, -1, 0, -1, 0, -1, 0, 0, -1, -1, 0, -1, 0, 0, -1, -1, 0, 0, 0, -1, -1, 0, -1};
    private static final int DIGEST_LENGTH = 32;
    private byte[][] C;
    private byte[] H;
    private byte[] K;
    private byte[] L;
    private byte[] M;
    byte[] S;
    private byte[] Sum;
    byte[] U;
    byte[] V;
    byte[] W;
    byte[] a;
    private long byteCount;
    private BlockCipher cipher;
    private byte[] sBox;
    short[] wS;
    short[] w_S;
    private byte[] xBuf;
    private int xBufOff;

    public GOST3411Digest() {
        this.H = new byte[32];
        this.L = new byte[32];
        this.M = new byte[32];
        this.Sum = new byte[32];
        this.C = (byte[][]) Array.newInstance(Byte.TYPE, 4, 32);
        this.xBuf = new byte[32];
        this.cipher = new GOST28147Engine();
        this.K = new byte[32];
        this.a = new byte[8];
        this.wS = new short[16];
        this.w_S = new short[16];
        this.S = new byte[32];
        this.U = new byte[32];
        this.V = new byte[32];
        this.W = new byte[32];
        this.sBox = GOST28147Engine.getSBox("D-A");
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));
        reset();
    }

    public GOST3411Digest(byte[] sBoxParam) {
        this.H = new byte[32];
        this.L = new byte[32];
        this.M = new byte[32];
        this.Sum = new byte[32];
        this.C = (byte[][]) Array.newInstance(Byte.TYPE, 4, 32);
        this.xBuf = new byte[32];
        this.cipher = new GOST28147Engine();
        this.K = new byte[32];
        this.a = new byte[8];
        this.wS = new short[16];
        this.w_S = new short[16];
        this.S = new byte[32];
        this.U = new byte[32];
        this.V = new byte[32];
        this.W = new byte[32];
        this.sBox = Arrays.clone(sBoxParam);
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));
        reset();
    }

    public GOST3411Digest(GOST3411Digest t) {
        this.H = new byte[32];
        this.L = new byte[32];
        this.M = new byte[32];
        this.Sum = new byte[32];
        this.C = (byte[][]) Array.newInstance(Byte.TYPE, 4, 32);
        this.xBuf = new byte[32];
        this.cipher = new GOST28147Engine();
        this.K = new byte[32];
        this.a = new byte[8];
        this.wS = new short[16];
        this.w_S = new short[16];
        this.S = new byte[32];
        this.U = new byte[32];
        this.V = new byte[32];
        this.W = new byte[32];
        reset(t);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "GOST3411";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return 32;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) {
        byte[] bArr = this.xBuf;
        int i = this.xBufOff;
        this.xBufOff = i + 1;
        bArr[i] = in;
        if (this.xBufOff == this.xBuf.length) {
            sumByteArray(this.xBuf);
            processBlock(this.xBuf, 0);
            this.xBufOff = 0;
        }
        this.byteCount++;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) {
        while (this.xBufOff != 0 && len > 0) {
            update(in[inOff]);
            inOff++;
            len--;
        }
        while (len > this.xBuf.length) {
            System.arraycopy(in, inOff, this.xBuf, 0, this.xBuf.length);
            sumByteArray(this.xBuf);
            processBlock(this.xBuf, 0);
            inOff += this.xBuf.length;
            len -= this.xBuf.length;
            this.byteCount += (long) this.xBuf.length;
        }
        while (len > 0) {
            update(in[inOff]);
            inOff++;
            len--;
        }
    }

    private byte[] P(byte[] in) {
        for (int k = 0; k < 8; k++) {
            this.K[k * 4] = in[k];
            this.K[(k * 4) + 1] = in[k + 8];
            this.K[(k * 4) + 2] = in[k + 16];
            this.K[(k * 4) + 3] = in[k + 24];
        }
        return this.K;
    }

    private byte[] A(byte[] in) {
        for (int j = 0; j < 8; j++) {
            this.a[j] = (byte) (in[j] ^ in[j + 8]);
        }
        System.arraycopy(in, 8, in, 0, 24);
        System.arraycopy(this.a, 0, in, 24, 8);
        return in;
    }

    private void E(byte[] key, byte[] s, int sOff, byte[] in, int inOff) {
        this.cipher.init(true, new KeyParameter(key));
        this.cipher.processBlock(in, inOff, s, sOff);
    }

    private void fw(byte[] in) {
        cpyBytesToShort(in, this.wS);
        this.w_S[15] = (short) (((((this.wS[0] ^ this.wS[1]) ^ this.wS[2]) ^ this.wS[3]) ^ this.wS[12]) ^ this.wS[15]);
        System.arraycopy(this.wS, 1, this.w_S, 0, 15);
        cpyShortToBytes(this.w_S, in);
    }

    /* access modifiers changed from: protected */
    public void processBlock(byte[] in, int inOff) {
        System.arraycopy(in, inOff, this.M, 0, 32);
        System.arraycopy(this.H, 0, this.U, 0, 32);
        System.arraycopy(this.M, 0, this.V, 0, 32);
        for (int j = 0; j < 32; j++) {
            this.W[j] = (byte) (this.U[j] ^ this.V[j]);
        }
        E(P(this.W), this.S, 0, this.H, 0);
        for (int i = 1; i < 4; i++) {
            byte[] tmpA = A(this.U);
            for (int j2 = 0; j2 < 32; j2++) {
                this.U[j2] = (byte) (tmpA[j2] ^ this.C[i][j2]);
            }
            this.V = A(A(this.V));
            for (int j3 = 0; j3 < 32; j3++) {
                this.W[j3] = (byte) (this.U[j3] ^ this.V[j3]);
            }
            E(P(this.W), this.S, i * 8, this.H, i * 8);
        }
        for (int n = 0; n < 12; n++) {
            fw(this.S);
        }
        for (int n2 = 0; n2 < 32; n2++) {
            this.S[n2] = (byte) (this.S[n2] ^ this.M[n2]);
        }
        fw(this.S);
        for (int n3 = 0; n3 < 32; n3++) {
            this.S[n3] = (byte) (this.H[n3] ^ this.S[n3]);
        }
        for (int n4 = 0; n4 < 61; n4++) {
            fw(this.S);
        }
        System.arraycopy(this.S, 0, this.H, 0, this.H.length);
    }

    private void finish() {
        Pack.longToLittleEndian(this.byteCount * 8, this.L, 0);
        while (this.xBufOff != 0) {
            update((byte) 0);
        }
        processBlock(this.L, 0);
        processBlock(this.Sum, 0);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) {
        finish();
        System.arraycopy(this.H, 0, out, outOff, this.H.length);
        reset();
        return 32;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this.byteCount = 0;
        this.xBufOff = 0;
        for (int i = 0; i < this.H.length; i++) {
            this.H[i] = 0;
        }
        for (int i2 = 0; i2 < this.L.length; i2++) {
            this.L[i2] = 0;
        }
        for (int i3 = 0; i3 < this.M.length; i3++) {
            this.M[i3] = 0;
        }
        for (int i4 = 0; i4 < this.C[1].length; i4++) {
            this.C[1][i4] = 0;
        }
        for (int i5 = 0; i5 < this.C[3].length; i5++) {
            this.C[3][i5] = 0;
        }
        for (int i6 = 0; i6 < this.Sum.length; i6++) {
            this.Sum[i6] = 0;
        }
        for (int i7 = 0; i7 < this.xBuf.length; i7++) {
            this.xBuf[i7] = 0;
        }
        System.arraycopy(C2, 0, this.C[2], 0, C2.length);
    }

    private void sumByteArray(byte[] in) {
        int carry = 0;
        for (int i = 0; i != this.Sum.length; i++) {
            int sum = (this.Sum[i] & 255) + (in[i] & 255) + carry;
            this.Sum[i] = (byte) sum;
            carry = sum >>> 8;
        }
    }

    private void cpyBytesToShort(byte[] S2, short[] wS2) {
        for (int i = 0; i < S2.length / 2; i++) {
            wS2[i] = (short) (((S2[(i * 2) + 1] << 8) & 65280) | (S2[i * 2] & 255));
        }
    }

    private void cpyShortToBytes(short[] wS2, byte[] S2) {
        for (int i = 0; i < S2.length / 2; i++) {
            S2[(i * 2) + 1] = (byte) (wS2[i] >> 8);
            S2[i * 2] = (byte) wS2[i];
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return 32;
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public Memoable copy() {
        return new GOST3411Digest(this);
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public void reset(Memoable other) {
        GOST3411Digest t = (GOST3411Digest) other;
        this.sBox = t.sBox;
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));
        reset();
        System.arraycopy(t.H, 0, this.H, 0, t.H.length);
        System.arraycopy(t.L, 0, this.L, 0, t.L.length);
        System.arraycopy(t.M, 0, this.M, 0, t.M.length);
        System.arraycopy(t.Sum, 0, this.Sum, 0, t.Sum.length);
        System.arraycopy(t.C[1], 0, this.C[1], 0, t.C[1].length);
        System.arraycopy(t.C[2], 0, this.C[2], 0, t.C[2].length);
        System.arraycopy(t.C[3], 0, this.C[3], 0, t.C[3].length);
        System.arraycopy(t.xBuf, 0, this.xBuf, 0, t.xBuf.length);
        this.xBufOff = t.xBufOff;
        this.byteCount = t.byteCount;
    }
}
