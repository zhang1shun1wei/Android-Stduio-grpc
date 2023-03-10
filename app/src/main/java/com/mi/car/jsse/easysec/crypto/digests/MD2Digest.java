package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.math.ec.Tnaf;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Memoable;

public class MD2Digest implements ExtendedDigest, Memoable {
    private static final int DIGEST_LENGTH = 16;
    private static final byte[] S = {41, 46, 67, -55, -94, -40, 124, 1, 61, 54, 84, -95, -20, -16, 6, 19, 98, -89, 5, -13, -64, -57, 115, -116, -104, -109, 43, -39, PSSSigner.TRAILER_IMPLICIT, 76, -126, -54, 30, -101, 87, 60, -3, -44, -32, 22, 103, 66, 111, 24, -118, 23, -27, 18, -66, 78, -60, -42, -38, -98, -34, 73, -96, -5, -11, -114, -69, 47, -18, 122, -87, 104, 121, -111, 21, -78, 7, 63, -108, -62, Tnaf.POW_2_WIDTH, -119, 11, 34, 95, 33, Byte.MIN_VALUE, Byte.MAX_VALUE, 93, -102, 90, -112, 50, 39, 53, 62, -52, -25, -65, -9, -105, 3, -1, 25, 48, -77, 72, -91, -75, -47, -41, 94, -110, 42, -84, 86, -86, -58, 79, -72, 56, -46, -106, -92, 125, -74, 118, -4, 107, -30, -100, 116, 4, -15, 69, -99, 112, 89, 100, 113, -121, 32, -122, 91, -49, 101, -26, 45, -88, 2, 27, 96, 37, -83, -82, -80, -71, -10, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, -93, 35, -35, 81, -81, 58, -61, 92, -7, -50, -70, -59, -22, 38, 44, 83, 13, 110, -123, 40, -124, 9, -45, -33, -51, -12, 65, -127, 77, 82, 106, -36, 55, -56, 108, -63, -85, -6, 36, -31, 123, 8, 12, -67, -79, 74, 120, -120, -107, -117, -29, 99, -24, 109, -23, -53, -43, -2, 59, 0, 29, 57, -14, -17, -73, 14, 102, 88, -48, -28, -90, 119, 114, -8, -21, 117, 75, 10, 49, 68, 80, -76, -113, -19, 31, 26, -37, -103, -115, 51, -97, 17, -125, 20};
    private byte[] C;
    private int COff;
    private byte[] M;
    private byte[] X;
    private int mOff;
    private int xOff;

    public MD2Digest() {
        this.X = new byte[48];
        this.M = new byte[16];
        this.C = new byte[16];
        reset();
    }

    public MD2Digest(MD2Digest t) {
        this.X = new byte[48];
        this.M = new byte[16];
        this.C = new byte[16];
        copyIn(t);
    }

    private void copyIn(MD2Digest t) {
        System.arraycopy(t.X, 0, this.X, 0, t.X.length);
        this.xOff = t.xOff;
        System.arraycopy(t.M, 0, this.M, 0, t.M.length);
        this.mOff = t.mOff;
        System.arraycopy(t.C, 0, this.C, 0, t.C.length);
        this.COff = t.COff;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "MD2";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] out, int outOff) {
        byte paddingByte = (byte) (this.M.length - this.mOff);
        for (int i = this.mOff; i < this.M.length; i++) {
            this.M[i] = paddingByte;
        }
        processCheckSum(this.M);
        processBlock(this.M);
        processBlock(this.C);
        System.arraycopy(this.X, this.xOff, out, outOff, 16);
        reset();
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        this.xOff = 0;
        for (int i = 0; i != this.X.length; i++) {
            this.X[i] = 0;
        }
        this.mOff = 0;
        for (int i2 = 0; i2 != this.M.length; i2++) {
            this.M[i2] = 0;
        }
        this.COff = 0;
        for (int i3 = 0; i3 != this.C.length; i3++) {
            this.C[i3] = 0;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte in) {
        byte[] bArr = this.M;
        int i = this.mOff;
        this.mOff = i + 1;
        bArr[i] = in;
        if (this.mOff == 16) {
            processCheckSum(this.M);
            processBlock(this.M);
            this.mOff = 0;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] in, int inOff, int len) {
        while (this.mOff != 0 && len > 0) {
            update(in[inOff]);
            inOff++;
            len--;
        }
        while (len > 16) {
            System.arraycopy(in, inOff, this.M, 0, 16);
            processCheckSum(this.M);
            processBlock(this.M);
            len -= 16;
            inOff += 16;
        }
        while (len > 0) {
            update(in[inOff]);
            inOff++;
            len--;
        }
    }

    /* access modifiers changed from: protected */
    public void processCheckSum(byte[] m) {
        byte b = this.C[15];
        for (int i = 0; i < 16; i++) {
            byte[] bArr = this.C;
            bArr[i] = (byte) (bArr[i] ^ S[(m[i] ^ b) & GF2Field.MASK]);
            b = this.C[i];
        }
    }

    /* access modifiers changed from: protected */
    public void processBlock(byte[] m) {
        for (int i = 0; i < 16; i++) {
            this.X[i + 16] = m[i];
            this.X[i + 32] = (byte) (m[i] ^ this.X[i]);
        }
        int t = 0;
        for (int j = 0; j < 18; j++) {
            for (int k = 0; k < 48; k++) {
                byte[] bArr = this.X;
                byte b = (byte) (bArr[k] ^ S[t]);
                bArr[k] = b;
                t = b & 255;
            }
            t = (t + j) % 256;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public Memoable copy() {
        return new MD2Digest(this);
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public void reset(Memoable other) {
        copyIn((MD2Digest) other);
    }
}
