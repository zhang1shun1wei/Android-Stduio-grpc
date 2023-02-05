package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.math.ec.Tnaf;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.Pack;

public final class TwofishEngine implements BlockCipher {
    private static final int BLOCK_SIZE = 16;
    private static final int GF256_FDBK = 361;
    private static final int GF256_FDBK_2 = 180;
    private static final int GF256_FDBK_4 = 90;
    private static final int INPUT_WHITEN = 0;
    private static final int MAX_KEY_BITS = 256;
    private static final int MAX_ROUNDS = 16;
    private static final int OUTPUT_WHITEN = 4;
    private static final byte[][] P = {new byte[]{-87, 103, -77, -24, 4, -3, -93, 118, -102, -110, Byte.MIN_VALUE, 120, -28, -35, -47, 56, 13, -58, 53, -104, 24, -9, -20, 108, 67, 117, 55, 38, -6, 19, -108, 72, -14, -48, -117, 48, -124, 84, -33, 35, 25, 91, 61, 89, -13, -82, -94, -126, 99, 1, -125, 46, -39, 81, -101, 124, -90, -21, -91, -66, 22, 12, -29, 97, -64, -116, 58, -11, 115, 44, 37, 11, -69, 78, -119, 107, 83, 106, -76, -15, -31, -26, -67, 69, -30, -12, -74, 102, -52, -107, 3, 86, -44, 28, 30, -41, -5, -61, -114, -75, -23, -49, -65, -70, -22, 119, 57, -81, 51, -55, 98, 113, -127, 121, 9, -83, 36, -51, -7, -40, -27, -59, -71, 77, 68, 8, -122, -25, -95, 29, -86, -19, 6, 112, -78, -46, 65, 123, -96, 17, 49, -62, 39, -112, 32, -10, 96, -1, -106, 92, -79, -85, -98, -100, 82, 27, 95, -109, 10, -17, -111, -123, 73, -18, 45, 79, -113, 59, 71, -121, 109, 70, -42, 62, 105, 100, 42, -50, -53, 47, -4, -105, 5, 122, -84, Byte.MAX_VALUE, -43, 26, 75, 14, -89, 90, 40, 20, 63, 41, -120, 60, 76, 2, -72, -38, -80, 23, 85, 31, -118, 125, 87, -57, -115, 116, -73, -60, -97, 114, 126, 21, 34, 18, 88, 7, -103, 52, 110, 80, -34, 104, 101, PSSSigner.TRAILER_IMPLICIT, -37, -8, -56, -88, 43, 64, -36, -2, 50, -92, -54, Tnaf.POW_2_WIDTH, 33, -16, -45, 93, 15, 0, 111, -99, 54, 66, 74, 94, -63, -32}, new byte[]{117, -13, -58, -12, -37, 123, -5, -56, 74, -45, -26, 107, 69, 125, -24, 75, -42, 50, -40, -3, 55, 113, -15, -31, 48, 15, -8, 27, -121, -6, 6, 63, 94, -70, -82, 91, -118, 0, PSSSigner.TRAILER_IMPLICIT, -99, 109, -63, -79, 14, Byte.MIN_VALUE, 93, -46, -43, -96, -124, 7, 20, -75, -112, 44, -93, -78, 115, 76, 84, -110, 116, 54, 81, 56, -80, -67, 90, -4, 96, 98, -106, 108, 66, -9, Tnaf.POW_2_WIDTH, 124, 40, 39, -116, 19, -107, -100, -57, 36, 70, 59, 112, -54, -29, -123, -53, 17, -48, -109, -72, -90, -125, 32, -1, -97, 119, -61, -52, 3, 111, 8, -65, 64, -25, 43, -30, 121, 12, -86, -126, 65, 58, -22, -71, -28, -102, -92, -105, 126, -38, 122, 23, 102, -108, -95, 29, 61, -16, -34, -77, 11, 114, -89, 28, -17, -47, 83, 62, -113, 51, 38, 95, -20, 118, 42, 73, -127, -120, -18, 33, -60, 26, -21, -39, -59, 57, -103, -51, -83, 49, -117, 1, 24, 35, -35, 31, 78, 45, -7, 72, 79, -14, 101, -114, 120, 92, 88, 25, -115, -27, -104, 87, 103, Byte.MAX_VALUE, 5, 100, -81, 99, -74, -2, -11, -73, 60, -91, -50, -23, 104, 68, -32, 77, 67, 105, 41, 46, -84, 21, 89, -88, 10, -98, 110, 71, -33, 52, 53, 106, -49, -36, 34, -55, -64, -101, -119, -44, -19, -85, 18, -94, 13, 82, -69, 2, 47, -87, -41, 97, 30, -76, 80, 4, -10, -62, 22, 37, -122, 86, 85, 9, -66, -111}};
    private static final int P_00 = 1;
    private static final int P_01 = 0;
    private static final int P_02 = 0;
    private static final int P_03 = 1;
    private static final int P_04 = 1;
    private static final int P_10 = 0;
    private static final int P_11 = 0;
    private static final int P_12 = 1;
    private static final int P_13 = 1;
    private static final int P_14 = 0;
    private static final int P_20 = 1;
    private static final int P_21 = 1;
    private static final int P_22 = 0;
    private static final int P_23 = 0;
    private static final int P_24 = 0;
    private static final int P_30 = 0;
    private static final int P_31 = 1;
    private static final int P_32 = 1;
    private static final int P_33 = 0;
    private static final int P_34 = 1;
    private static final int ROUNDS = 16;
    private static final int ROUND_SUBKEYS = 8;
    private static final int RS_GF_FDBK = 333;
    private static final int SK_BUMP = 16843009;
    private static final int SK_ROTL = 9;
    private static final int SK_STEP = 33686018;
    private static final int TOTAL_SUBKEYS = 40;
    private boolean encrypting = false;
    private int[] gMDS0 = new int[256];
    private int[] gMDS1 = new int[256];
    private int[] gMDS2 = new int[256];
    private int[] gMDS3 = new int[256];
    private int[] gSBox;
    private int[] gSubKeys;
    private int k64Cnt = 0;
    private byte[] workingKey = null;

    public TwofishEngine() {
        int[] m1 = new int[2];
        int[] mX = new int[2];
        int[] mY = new int[2];
        for (int i = 0; i < 256; i++) {
            int j = P[0][i] & 255;
            m1[0] = j;
            mX[0] = Mx_X(j) & GF2Field.MASK;
            mY[0] = Mx_Y(j) & GF2Field.MASK;
            int j2 = P[1][i] & 255;
            m1[1] = j2;
            mX[1] = Mx_X(j2) & GF2Field.MASK;
            mY[1] = Mx_Y(j2) & GF2Field.MASK;
            this.gMDS0[i] = m1[1] | (mX[1] << 8) | (mY[1] << 16) | (mY[1] << 24);
            this.gMDS1[i] = mY[0] | (mY[0] << 8) | (mX[0] << 16) | (m1[0] << 24);
            this.gMDS2[i] = mX[1] | (mY[1] << 8) | (m1[1] << 16) | (mY[1] << 24);
            this.gMDS3[i] = mX[0] | (m1[0] << 8) | (mY[0] << 16) | (mX[0] << 24);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean encrypting2, CipherParameters params) {
        if (params instanceof KeyParameter) {
            this.encrypting = encrypting2;
            this.workingKey = ((KeyParameter) params).getKey();
            switch (this.workingKey.length * 8) {
                case 128:
                case BERTags.PRIVATE:
                case 256:
                    this.k64Cnt = this.workingKey.length / 8;
                    setKey(this.workingKey);
                    return;
                default:
                    throw new IllegalArgumentException("Key length not 128/192/256 bits.");
            }
        } else {
            throw new IllegalArgumentException("invalid parameter passed to Twofish init - " + params.getClass().getName());
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "Twofish";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        if (this.workingKey == null) {
            throw new IllegalStateException("Twofish not initialised");
        } else if (inOff + 16 > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff + 16 > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else if (this.encrypting) {
            encryptBlock(in, inOff, out, outOff);
            return 16;
        } else {
            decryptBlock(in, inOff, out, outOff);
            return 16;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
        if (this.workingKey != null) {
            setKey(this.workingKey);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    /* JADX INFO: Can't fix incorrect switch cases order, some code will duplicate */
    private void setKey(byte[] key) {
        int[] k32e = new int[4];
        int[] k32o = new int[4];
        int[] sBoxKeys = new int[4];
        this.gSubKeys = new int[40];
        for (int i = 0; i < this.k64Cnt; i++) {
            int p = i * 8;
            k32e[i] = Pack.littleEndianToInt(key, p);
            k32o[i] = Pack.littleEndianToInt(key, p + 4);
            sBoxKeys[(this.k64Cnt - 1) - i] = RS_MDS_Encode(k32e[i], k32o[i]);
        }
        for (int i2 = 0; i2 < 20; i2++) {
            int q = i2 * SK_STEP;
            int A = F32(q, k32e);
            int B = Integers.rotateLeft(F32(SK_BUMP + q, k32o), 8);
            int A2 = A + B;
            this.gSubKeys[i2 * 2] = A2;
            int A3 = A2 + B;
            this.gSubKeys[(i2 * 2) + 1] = (A3 << 9) | (A3 >>> 23);
        }
        int k0 = sBoxKeys[0];
        int k1 = sBoxKeys[1];
        int k2 = sBoxKeys[2];
        int k3 = sBoxKeys[3];
        this.gSBox = new int[1024];
        for (int i3 = 0; i3 < 256; i3++) {
            int b3 = i3;
            int b2 = i3;
            int b1 = i3;
            int b0 = i3;
            switch (this.k64Cnt & 3) {
                case 0:
                    b0 = (P[1][b0] & 255) ^ b0(k3);
                    b1 = (P[0][b1] & 255) ^ b1(k3);
                    b2 = (P[0][b2] & 255) ^ b2(k3);
                    b3 = (P[1][b3] & 255) ^ b3(k3);
                    b0 = (P[1][b0] & 255) ^ b0(k2);
                    b1 = (P[1][b1] & 255) ^ b1(k2);
                    b2 = (P[0][b2] & 255) ^ b2(k2);
                    b3 = (P[0][b3] & 255) ^ b3(k2);
                    break;
                case 1:
                    this.gSBox[i3 * 2] = this.gMDS0[(P[0][b0] & 255) ^ b0(k0)];
                    this.gSBox[(i3 * 2) + 1] = this.gMDS1[(P[0][b1] & 255) ^ b1(k0)];
                    this.gSBox[(i3 * 2) + 512] = this.gMDS2[(P[1][b2] & 255) ^ b2(k0)];
                    this.gSBox[(i3 * 2) + 513] = this.gMDS3[(P[1][b3] & 255) ^ b3(k0)];
                    continue;
                case 2:
                    break;
                case 3:
                    b0 = (P[1][b0] & 255) ^ b0(k2);
                    b1 = (P[1][b1] & 255) ^ b1(k2);
                    b2 = (P[0][b2] & 255) ^ b2(k2);
                    b3 = (P[0][b3] & 255) ^ b3(k2);
                    break;
                default:
            }
            this.gSBox[i3 * 2] = this.gMDS0[(P[0][(P[0][b0] & 255) ^ b0(k1)] & 255) ^ b0(k0)];
            this.gSBox[(i3 * 2) + 1] = this.gMDS1[(P[0][(P[1][b1] & 255) ^ b1(k1)] & 255) ^ b1(k0)];
            this.gSBox[(i3 * 2) + 512] = this.gMDS2[(P[1][(P[0][b2] & 255) ^ b2(k1)] & 255) ^ b2(k0)];
            this.gSBox[(i3 * 2) + 513] = this.gMDS3[(P[1][(P[1][b3] & 255) ^ b3(k1)] & 255) ^ b3(k0)];
        }
    }

    private void encryptBlock(byte[] src, int srcIndex, byte[] dst, int dstIndex) {
        int x0 = Pack.littleEndianToInt(src, srcIndex) ^ this.gSubKeys[0];
        int x1 = Pack.littleEndianToInt(src, srcIndex + 4) ^ this.gSubKeys[1];
        int x2 = Pack.littleEndianToInt(src, srcIndex + 8) ^ this.gSubKeys[2];
        int x3 = Pack.littleEndianToInt(src, srcIndex + 12) ^ this.gSubKeys[3];
        int k = 8;
        for (int r = 0; r < 16; r += 2) {
            int t0 = Fe32_0(x0);
            int t1 = Fe32_3(x1);
            int k2 = k + 1;
            x2 = Integers.rotateRight(x2 ^ ((t0 + t1) + this.gSubKeys[k]), 1);
            int k3 = k2 + 1;
            x3 = Integers.rotateLeft(x3, 1) ^ (((t1 * 2) + t0) + this.gSubKeys[k2]);
            int t02 = Fe32_0(x2);
            int t12 = Fe32_3(x3);
            int k4 = k3 + 1;
            x0 = Integers.rotateRight(x0 ^ ((t02 + t12) + this.gSubKeys[k3]), 1);
            k = k4 + 1;
            x1 = Integers.rotateLeft(x1, 1) ^ (((t12 * 2) + t02) + this.gSubKeys[k4]);
        }
        Pack.intToLittleEndian(this.gSubKeys[4] ^ x2, dst, dstIndex);
        Pack.intToLittleEndian(this.gSubKeys[5] ^ x3, dst, dstIndex + 4);
        Pack.intToLittleEndian(this.gSubKeys[6] ^ x0, dst, dstIndex + 8);
        Pack.intToLittleEndian(this.gSubKeys[7] ^ x1, dst, dstIndex + 12);
    }

    private void decryptBlock(byte[] src, int srcIndex, byte[] dst, int dstIndex) {
        int x2 = Pack.littleEndianToInt(src, srcIndex) ^ this.gSubKeys[4];
        int x3 = Pack.littleEndianToInt(src, srcIndex + 4) ^ this.gSubKeys[5];
        int x0 = Pack.littleEndianToInt(src, srcIndex + 8) ^ this.gSubKeys[6];
        int x1 = Pack.littleEndianToInt(src, srcIndex + 12) ^ this.gSubKeys[7];
        int k = 39;
        for (int r = 0; r < 16; r += 2) {
            int t0 = Fe32_0(x2);
            int t1 = Fe32_3(x3);
            int k2 = k - 1;
            int x12 = x1 ^ (((t1 * 2) + t0) + this.gSubKeys[k]);
            int k3 = k2 - 1;
            x0 = Integers.rotateLeft(x0, 1) ^ ((t0 + t1) + this.gSubKeys[k2]);
            x1 = Integers.rotateRight(x12, 1);
            int t02 = Fe32_0(x0);
            int t12 = Fe32_3(x1);
            int k4 = k3 - 1;
            int x32 = x3 ^ (((t12 * 2) + t02) + this.gSubKeys[k3]);
            k = k4 - 1;
            x2 = Integers.rotateLeft(x2, 1) ^ ((t02 + t12) + this.gSubKeys[k4]);
            x3 = Integers.rotateRight(x32, 1);
        }
        Pack.intToLittleEndian(this.gSubKeys[0] ^ x0, dst, dstIndex);
        Pack.intToLittleEndian(this.gSubKeys[1] ^ x1, dst, dstIndex + 4);
        Pack.intToLittleEndian(this.gSubKeys[2] ^ x2, dst, dstIndex + 8);
        Pack.intToLittleEndian(this.gSubKeys[3] ^ x3, dst, dstIndex + 12);
    }

    /* JADX INFO: Can't fix incorrect switch cases order, some code will duplicate */
    private int F32(int x, int[] k32) {
        int b0 = b0(x);
        int b1 = b1(x);
        int b2 = b2(x);
        int b3 = b3(x);
        int k0 = k32[0];
        int k1 = k32[1];
        int k2 = k32[2];
        int k3 = k32[3];
        switch (this.k64Cnt & 3) {
            case 0:
                b0 = (P[1][b0] & 255) ^ b0(k3);
                b1 = (P[0][b1] & 255) ^ b1(k3);
                b2 = (P[0][b2] & 255) ^ b2(k3);
                b3 = (P[1][b3] & 255) ^ b3(k3);
                b0 = (P[1][b0] & 255) ^ b0(k2);
                b1 = (P[1][b1] & 255) ^ b1(k2);
                b2 = (P[0][b2] & 255) ^ b2(k2);
                b3 = (P[0][b3] & 255) ^ b3(k2);
                break;
            case 1:
                return ((this.gMDS0[(P[0][b0] & 255) ^ b0(k0)] ^ this.gMDS1[(P[0][b1] & 255) ^ b1(k0)]) ^ this.gMDS2[(P[1][b2] & 255) ^ b2(k0)]) ^ this.gMDS3[(P[1][b3] & 255) ^ b3(k0)];
            case 2:
                break;
            case 3:
                b0 = (P[1][b0] & 255) ^ b0(k2);
                b1 = (P[1][b1] & 255) ^ b1(k2);
                b2 = (P[0][b2] & 255) ^ b2(k2);
                b3 = (P[0][b3] & 255) ^ b3(k2);
                break;
            default:
                return 0;
        }
        return ((this.gMDS0[(P[0][(P[0][b0] & 255) ^ b0(k1)] & 255) ^ b0(k0)] ^ this.gMDS1[(P[0][(P[1][b1] & 255) ^ b1(k1)] & 255) ^ b1(k0)]) ^ this.gMDS2[(P[1][(P[0][b2] & 255) ^ b2(k1)] & 255) ^ b2(k0)]) ^ this.gMDS3[(P[1][(P[1][b3] & 255) ^ b3(k1)] & 255) ^ b3(k0)];
    }

    private int RS_MDS_Encode(int k0, int k1) {
        int r = k1;
        for (int i = 0; i < 4; i++) {
            r = RS_rem(r);
        }
        int r2 = r ^ k0;
        for (int i2 = 0; i2 < 4; i2++) {
            r2 = RS_rem(r2);
        }
        return r2;
    }

    private int RS_rem(int x) {
        int i;
        int i2 = 0;
        int b = (x >>> 24) & GF2Field.MASK;
        int i3 = b << 1;
        if ((b & 128) != 0) {
            i = RS_GF_FDBK;
        } else {
            i = 0;
        }
        int g2 = (i ^ i3) & GF2Field.MASK;
        int i4 = b >>> 1;
        if ((b & 1) != 0) {
            i2 = 166;
        }
        int g3 = (i2 ^ i4) ^ g2;
        return ((((x << 8) ^ (g3 << 24)) ^ (g2 << 16)) ^ (g3 << 8)) ^ b;
    }

    private int LFSR1(int x) {
        return ((x & 1) != 0 ? GF256_FDBK_2 : 0) ^ (x >> 1);
    }

    private int LFSR2(int x) {
        int i = 0;
        int i2 = ((x & 2) != 0 ? GF256_FDBK_2 : 0) ^ (x >> 2);
        if ((x & 1) != 0) {
            i = GF256_FDBK_4;
        }
        return i ^ i2;
    }

    private int Mx_X(int x) {
        return LFSR2(x) ^ x;
    }

    private int Mx_Y(int x) {
        return (LFSR1(x) ^ x) ^ LFSR2(x);
    }

    private int b0(int x) {
        return x & GF2Field.MASK;
    }

    private int b1(int x) {
        return (x >>> 8) & GF2Field.MASK;
    }

    private int b2(int x) {
        return (x >>> 16) & GF2Field.MASK;
    }

    private int b3(int x) {
        return (x >>> 24) & GF2Field.MASK;
    }

    private int Fe32_0(int x) {
        return ((this.gSBox[((x & GF2Field.MASK) * 2) + 0] ^ this.gSBox[(((x >>> 8) & GF2Field.MASK) * 2) + 1]) ^ this.gSBox[(((x >>> 16) & GF2Field.MASK) * 2) + 512]) ^ this.gSBox[(((x >>> 24) & GF2Field.MASK) * 2) + 513];
    }

    private int Fe32_3(int x) {
        return ((this.gSBox[(((x >>> 24) & GF2Field.MASK) * 2) + 0] ^ this.gSBox[((x & GF2Field.MASK) * 2) + 1]) ^ this.gSBox[(((x >>> 8) & GF2Field.MASK) * 2) + 512]) ^ this.gSBox[(((x >>> 16) & GF2Field.MASK) * 2) + 513];
    }
}
