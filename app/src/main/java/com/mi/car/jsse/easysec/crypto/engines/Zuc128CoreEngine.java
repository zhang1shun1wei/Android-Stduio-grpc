package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.StreamCipher;
import com.mi.car.jsse.easysec.crypto.digests.Blake2xsDigest;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.math.ec.Tnaf;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Memoable;

public class Zuc128CoreEngine implements StreamCipher, Memoable {
    private static final short[] EK_d = {17623, 9916, 25195, 4958, 22409, 13794, 28981, 2479, 19832, 12051, 27588, 6897, 24102, 15437, 30874, 18348};
    private static final byte[] S0 = {62, 114, 91, 71, -54, -32, 0, 51, 4, -47, 84, -104, 9, -71, 109, -53, 123, 27, -7, 50, -81, -99, 106, -91, -72, 45, -4, 29, 8, 83, 3, -112, 77, 78, -124, -103, -28, -50, -39, -111, -35, -74, -123, 72, -117, 41, 110, -84, -51, -63, -8, 30, 115, 67, 105, -58, -75, -67, -3, 57, 99, 32, -44, 56, 118, 125, -78, -89, -49, -19, 87, -59, -13, 44, -69, 20, 33, 6, 85, -101, -29, -17, 94, 49, 79, Byte.MAX_VALUE, 90, -92, 13, -126, 81, 73, 95, -70, 88, 28, 74, 22, -43, 23, -88, -110, 36, 31, -116, -1, -40, -82, 46, 1, -45, -83, 59, 75, -38, 70, -21, -55, -34, -102, -113, -121, -41, 58, Byte.MIN_VALUE, 111, 47, -56, -79, -76, 55, -9, 10, 34, 19, 40, 124, -52, 60, -119, -57, -61, -106, 86, 7, -65, 126, -16, 11, 43, -105, 82, 53, 65, 121, 97, -90, 76, Tnaf.POW_2_WIDTH, -2, PSSSigner.TRAILER_IMPLICIT, 38, -107, -120, -118, -80, -93, -5, -64, 24, -108, -14, -31, -27, -23, 93, -48, -36, 17, 102, 100, 92, -20, 89, 66, 117, 18, -11, 116, -100, -86, 35, 14, -122, -85, -66, 42, 2, -25, 103, -26, 68, -94, 108, -62, -109, -97, -15, -10, -6, 54, -46, 80, 104, -98, 98, 113, 21, 61, -42, 64, -60, -30, 15, -114, -125, 119, 107, 37, 5, 63, 12, 48, -22, 112, -73, -95, -24, -87, 101, -115, 39, 26, -37, -127, -77, -96, -12, 69, 122, 25, -33, -18, 120, 52, 96};
    private static final byte[] S1 = {85, -62, 99, 113, 59, -56, 71, -122, -97, 60, -38, 91, 41, -86, -3, 119, -116, -59, -108, 12, -90, 26, 19, 0, -29, -88, 22, 114, 64, -7, -8, 66, 68, 38, 104, -106, -127, -39, 69, 62, Tnaf.POW_2_WIDTH, 118, -58, -89, -117, 57, 67, -31, 58, -75, 86, 42, -64, 109, -77, 5, 34, 102, -65, -36, 11, -6, 98, 72, -35, 32, 17, 6, 54, -55, -63, -49, -10, 39, 82, -69, 105, -11, -44, -121, Byte.MAX_VALUE, -124, 76, -46, -100, 87, -92, PSSSigner.TRAILER_IMPLICIT, 79, -102, -33, -2, -42, -115, 122, -21, 43, 83, -40, 92, -95, 20, 23, -5, 35, -43, 125, 48, 103, 115, 8, 9, -18, -73, 112, 63, 97, -78, 25, -114, 78, -27, 75, -109, -113, 93, -37, -87, -83, -15, -82, 46, -53, 13, -4, -12, 45, 70, 110, 29, -105, -24, -47, -23, 77, 55, -91, 117, 94, -125, -98, -85, -126, -99, -71, 28, -32, -51, 73, -119, 1, -74, -67, 88, 36, -94, 95, 56, 120, -103, 21, -112, 80, -72, -107, -28, -48, -111, -57, -50, -19, 15, -76, 111, -96, -52, -16, 2, 74, 121, -61, -34, -93, -17, -22, 81, -26, 107, 24, -20, 27, 44, Byte.MIN_VALUE, -9, 116, -25, -1, 33, 90, 106, 84, 30, 65, 49, -110, 53, -60, 51, 7, 10, -70, 126, 14, 52, -120, -79, -104, 124, -13, 61, 96, 108, 123, -54, -45, 31, 50, 101, 4, 40, 100, -66, -123, -101, 47, 89, -118, -41, -80, 37, -84, -81, 18, 3, -30, -14};
    private final int[] BRC;
    private final int[] F;
    private final int[] LFSR;
    private final byte[] keyStream;
    private int theIndex;
    private int theIterations;
    private Zuc128CoreEngine theResetState;

    protected Zuc128CoreEngine() {
        this.LFSR = new int[16];
        this.F = new int[2];
        this.BRC = new int[4];
        this.keyStream = new byte[4];
    }

    protected Zuc128CoreEngine(Zuc128CoreEngine pSource) {
        this.LFSR = new int[16];
        this.F = new int[2];
        this.BRC = new int[4];
        this.keyStream = new byte[4];
        reset(pSource);
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public void init(boolean forEncryption, CipherParameters params) {
        CipherParameters myParams = params;
        byte[] newKey = null;
        byte[] newIV = null;
        if (myParams instanceof ParametersWithIV) {
            ParametersWithIV ivParams = (ParametersWithIV) myParams;
            newIV = ivParams.getIV();
            myParams = ivParams.getParameters();
        }
        if (myParams instanceof KeyParameter) {
            newKey = ((KeyParameter) myParams).getKey();
        }
        this.theIndex = 0;
        this.theIterations = 0;
        setKeyAndIV(newKey, newIV);
        this.theResetState = (Zuc128CoreEngine) copy();
    }

    /* access modifiers changed from: protected */
    public int getMaxIterations() {
        return 2047;
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        return "Zuc-128";
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) {
        if (this.theResetState == null) {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        } else if (inOff + len > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff + len > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            for (int i = 0; i < len; i++) {
                out[i + outOff] = returnByte(in[i + inOff]);
            }
            return len;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public void reset() {
        if (this.theResetState != null) {
            reset(this.theResetState);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public byte returnByte(byte in) {
        if (this.theIndex == 0) {
            makeKeyStream();
        }
        byte out = (byte) (this.keyStream[this.theIndex] ^ in);
        this.theIndex = (this.theIndex + 1) % 4;
        return out;
    }

    public static void encode32be(int val, byte[] buf, int off) {
        buf[off] = (byte) (val >> 24);
        buf[off + 1] = (byte) (val >> 16);
        buf[off + 2] = (byte) (val >> 8);
        buf[off + 3] = (byte) val;
    }

    private int AddM(int a, int b) {
        int c = a + b;
        return (Integer.MAX_VALUE & c) + (c >>> 31);
    }

    private static int MulByPow2(int x, int k) {
        return ((x << k) | (x >>> (31 - k))) & Integer.MAX_VALUE;
    }

    private void LFSRWithInitialisationMode(int u) {
        int f = AddM(AddM(AddM(AddM(AddM(AddM(this.LFSR[0], MulByPow2(this.LFSR[0], 8)), MulByPow2(this.LFSR[4], 20)), MulByPow2(this.LFSR[10], 21)), MulByPow2(this.LFSR[13], 17)), MulByPow2(this.LFSR[15], 15)), u);
        this.LFSR[0] = this.LFSR[1];
        this.LFSR[1] = this.LFSR[2];
        this.LFSR[2] = this.LFSR[3];
        this.LFSR[3] = this.LFSR[4];
        this.LFSR[4] = this.LFSR[5];
        this.LFSR[5] = this.LFSR[6];
        this.LFSR[6] = this.LFSR[7];
        this.LFSR[7] = this.LFSR[8];
        this.LFSR[8] = this.LFSR[9];
        this.LFSR[9] = this.LFSR[10];
        this.LFSR[10] = this.LFSR[11];
        this.LFSR[11] = this.LFSR[12];
        this.LFSR[12] = this.LFSR[13];
        this.LFSR[13] = this.LFSR[14];
        this.LFSR[14] = this.LFSR[15];
        this.LFSR[15] = f;
    }

    private void LFSRWithWorkMode() {
        int f = AddM(AddM(AddM(AddM(AddM(this.LFSR[0], MulByPow2(this.LFSR[0], 8)), MulByPow2(this.LFSR[4], 20)), MulByPow2(this.LFSR[10], 21)), MulByPow2(this.LFSR[13], 17)), MulByPow2(this.LFSR[15], 15));
        this.LFSR[0] = this.LFSR[1];
        this.LFSR[1] = this.LFSR[2];
        this.LFSR[2] = this.LFSR[3];
        this.LFSR[3] = this.LFSR[4];
        this.LFSR[4] = this.LFSR[5];
        this.LFSR[5] = this.LFSR[6];
        this.LFSR[6] = this.LFSR[7];
        this.LFSR[7] = this.LFSR[8];
        this.LFSR[8] = this.LFSR[9];
        this.LFSR[9] = this.LFSR[10];
        this.LFSR[10] = this.LFSR[11];
        this.LFSR[11] = this.LFSR[12];
        this.LFSR[12] = this.LFSR[13];
        this.LFSR[13] = this.LFSR[14];
        this.LFSR[14] = this.LFSR[15];
        this.LFSR[15] = f;
    }

    private void BitReorganization() {
        this.BRC[0] = ((this.LFSR[15] & 2147450880) << 1) | (this.LFSR[14] & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH);
        this.BRC[1] = ((this.LFSR[11] & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH) << 16) | (this.LFSR[9] >>> 15);
        this.BRC[2] = ((this.LFSR[7] & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH) << 16) | (this.LFSR[5] >>> 15);
        this.BRC[3] = ((this.LFSR[2] & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH) << 16) | (this.LFSR[0] >>> 15);
    }

    static int ROT(int a, int k) {
        return (a << k) | (a >>> (32 - k));
    }

    private static int L1(int X) {
        return (((ROT(X, 2) ^ X) ^ ROT(X, 10)) ^ ROT(X, 18)) ^ ROT(X, 24);
    }

    private static int L2(int X) {
        return (((ROT(X, 8) ^ X) ^ ROT(X, 14)) ^ ROT(X, 22)) ^ ROT(X, 30);
    }

    private static int MAKEU32(byte a, byte b, byte c, byte d) {
        return ((a & 255) << 24) | ((b & 255) << 16) | ((c & 255) << 8) | (d & 255);
    }

    /* access modifiers changed from: package-private */
    public int F() {
        int W = (this.BRC[0] ^ this.F[0]) + this.F[1];
        int W1 = this.F[0] + this.BRC[1];
        int W2 = this.F[1] ^ this.BRC[2];
        int u = L1((W1 << 16) | (W2 >>> 16));
        int v = L2((W2 << 16) | (W1 >>> 16));
        this.F[0] = MAKEU32(S0[u >>> 24], S1[(u >>> 16) & GF2Field.MASK], S0[(u >>> 8) & GF2Field.MASK], S1[u & GF2Field.MASK]);
        this.F[1] = MAKEU32(S0[v >>> 24], S1[(v >>> 16) & GF2Field.MASK], S0[(v >>> 8) & GF2Field.MASK], S1[v & GF2Field.MASK]);
        return W;
    }

    private static int MAKEU31(byte a, short b, byte c) {
        return ((a & 255) << 23) | ((65535 & b) << 8) | (c & 255);
    }

    /* access modifiers changed from: protected */
    public void setKeyAndIV(int[] pLFSR, byte[] k, byte[] iv) {
        if (k == null || k.length != 16) {
            throw new IllegalArgumentException("A key of 16 bytes is needed");
        } else if (iv == null || iv.length != 16) {
            throw new IllegalArgumentException("An IV of 16 bytes is needed");
        } else {
            this.LFSR[0] = MAKEU31(k[0], EK_d[0], iv[0]);
            this.LFSR[1] = MAKEU31(k[1], EK_d[1], iv[1]);
            this.LFSR[2] = MAKEU31(k[2], EK_d[2], iv[2]);
            this.LFSR[3] = MAKEU31(k[3], EK_d[3], iv[3]);
            this.LFSR[4] = MAKEU31(k[4], EK_d[4], iv[4]);
            this.LFSR[5] = MAKEU31(k[5], EK_d[5], iv[5]);
            this.LFSR[6] = MAKEU31(k[6], EK_d[6], iv[6]);
            this.LFSR[7] = MAKEU31(k[7], EK_d[7], iv[7]);
            this.LFSR[8] = MAKEU31(k[8], EK_d[8], iv[8]);
            this.LFSR[9] = MAKEU31(k[9], EK_d[9], iv[9]);
            this.LFSR[10] = MAKEU31(k[10], EK_d[10], iv[10]);
            this.LFSR[11] = MAKEU31(k[11], EK_d[11], iv[11]);
            this.LFSR[12] = MAKEU31(k[12], EK_d[12], iv[12]);
            this.LFSR[13] = MAKEU31(k[13], EK_d[13], iv[13]);
            this.LFSR[14] = MAKEU31(k[14], EK_d[14], iv[14]);
            this.LFSR[15] = MAKEU31(k[15], EK_d[15], iv[15]);
        }
    }

    private void setKeyAndIV(byte[] k, byte[] iv) {
        setKeyAndIV(this.LFSR, k, iv);
        this.F[0] = 0;
        this.F[1] = 0;
        for (int nCount = 32; nCount > 0; nCount--) {
            BitReorganization();
            LFSRWithInitialisationMode(F() >>> 1);
        }
        BitReorganization();
        F();
        LFSRWithWorkMode();
    }

    private void makeKeyStream() {
        encode32be(makeKeyStreamWord(), this.keyStream, 0);
    }

    /* access modifiers changed from: protected */
    public int makeKeyStreamWord() {
        int i = this.theIterations;
        this.theIterations = i + 1;
        if (i >= getMaxIterations()) {
            throw new IllegalStateException("Too much data processed by singleKey/IV");
        }
        BitReorganization();
        int result = F() ^ this.BRC[3];
        LFSRWithWorkMode();
        return result;
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public Memoable copy() {
        return new Zuc128CoreEngine(this);
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public void reset(Memoable pState) {
        Zuc128CoreEngine e = (Zuc128CoreEngine) pState;
        System.arraycopy(e.LFSR, 0, this.LFSR, 0, this.LFSR.length);
        System.arraycopy(e.F, 0, this.F, 0, this.F.length);
        System.arraycopy(e.BRC, 0, this.BRC, 0, this.BRC.length);
        System.arraycopy(e.keyStream, 0, this.keyStream, 0, this.keyStream.length);
        this.theIndex = e.theIndex;
        this.theIterations = e.theIterations;
        this.theResetState = e;
    }
}
