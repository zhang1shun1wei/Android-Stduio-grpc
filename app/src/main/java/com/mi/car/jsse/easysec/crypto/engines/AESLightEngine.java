package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.StatelessProcessing;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.math.ec.Tnaf;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Pack;
import java.lang.reflect.Array;

public class AESLightEngine implements BlockCipher, StatelessProcessing {
    private static final int BLOCK_SIZE = 16;
    private static final byte[] S = {99, 124, 119, 123, -14, 107, 111, -59, 48, 1, 103, 43, -2, -41, -85, 118, -54, -126, -55, 125, -6, 89, 71, -16, -83, -44, -94, -81, -100, -92, 114, -64, -73, -3, -109, 38, 54, 63, -9, -52, 52, -91, -27, -15, 113, -40, 49, 21, 4, -57, 35, -61, 24, -106, 5, -102, 7, 18, Byte.MIN_VALUE, -30, -21, 39, -78, 117, 9, -125, 44, 26, 27, 110, 90, -96, 82, 59, -42, -77, 41, -29, 47, -124, 83, -47, 0, -19, 32, -4, -79, 91, 106, -53, -66, 57, 74, 76, 88, -49, -48, -17, -86, -5, 67, 77, 51, -123, 69, -7, 2, Byte.MAX_VALUE, 80, 60, -97, -88, 81, -93, 64, -113, -110, -99, 56, -11, PSSSigner.TRAILER_IMPLICIT, -74, -38, 33, Tnaf.POW_2_WIDTH, -1, -13, -46, -51, 12, 19, -20, 95, -105, 68, 23, -60, -89, 126, 61, 100, 93, 25, 115, 96, -127, 79, -36, 34, 42, -112, -120, 70, -18, -72, 20, -34, 94, 11, -37, -32, 50, 58, 10, 73, 6, 36, 92, -62, -45, -84, 98, -111, -107, -28, 121, -25, -56, 55, 109, -115, -43, 78, -87, 108, 86, -12, -22, 101, 122, -82, 8, -70, 120, 37, 46, 28, -90, -76, -58, -24, -35, 116, 31, 75, -67, -117, -118, 112, 62, -75, 102, 72, 3, -10, 14, 97, 53, 87, -71, -122, -63, 29, -98, -31, -8, -104, 17, 105, -39, -114, -108, -101, 30, -121, -23, -50, 85, 40, -33, -116, -95, -119, 13, -65, -26, 66, 104, 65, -103, 45, 15, -80, 84, -69, 22};
    private static final byte[] Si = {82, 9, 106, -43, 48, 54, -91, 56, -65, 64, -93, -98, -127, -13, -41, -5, 124, -29, 57, -126, -101, 47, -1, -121, 52, -114, 67, 68, -60, -34, -23, -53, 84, 123, -108, 50, -90, -62, 35, 61, -18, 76, -107, 11, 66, -6, -61, 78, 8, 46, -95, 102, 40, -39, 36, -78, 118, 91, -94, 73, 109, -117, -47, 37, 114, -8, -10, 100, -122, 104, -104, 22, -44, -92, 92, -52, 93, 101, -74, -110, 108, 112, 72, 80, -3, -19, -71, -38, 94, 21, 70, 87, -89, -115, -99, -124, -112, -40, -85, 0, -116, PSSSigner.TRAILER_IMPLICIT, -45, 10, -9, -28, 88, 5, -72, -77, 69, 6, -48, 44, 30, -113, -54, 63, 15, 2, -63, -81, -67, 3, 1, 19, -118, 107, 58, -111, 17, 65, 79, 103, -36, -22, -105, -14, -49, -50, -16, -76, -26, 115, -106, -84, 116, 34, -25, -83, 53, -123, -30, -7, 55, -24, 28, 117, -33, 110, 71, -15, 26, 113, 29, 41, -59, -119, 111, -73, 98, 14, -86, 24, -66, 27, -4, 86, 62, 75, -58, -46, 121, 32, -102, -37, -64, -2, 120, -51, 90, -12, 31, -35, -88, 51, -120, 7, -57, 49, -79, 18, Tnaf.POW_2_WIDTH, 89, 39, Byte.MIN_VALUE, -20, 95, 96, 81, Byte.MAX_VALUE, -87, 25, -75, 74, 13, 45, -27, 122, -97, -109, -55, -100, -17, -96, -32, 59, 77, -82, 42, -11, -80, -56, -21, -69, 60, -125, 83, -103, 97, 23, 43, 4, 126, -70, 119, -42, 38, -31, 105, 20, 99, 85, 33, 12, 125};
    private static final int m1 = -2139062144;
    private static final int m2 = 2139062143;
    private static final int m3 = 27;
    private static final int m4 = -1061109568;
    private static final int m5 = 1061109567;
    private static final int[] rcon = {1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145};
    private int ROUNDS;
    private int[][] WorkingKey = null;
    private boolean forEncryption;

    private static int shift(int r, int shift) {
        return (r >>> shift) | (r << (-shift));
    }

    private static int FFmulX(int x) {
        return ((m2 & x) << 1) ^ (((m1 & x) >>> 7) * 27);
    }

    private static int FFmulX2(int x) {
        int t0 = (m5 & x) << 2;
        int t1 = x & m4;
        int t12 = t1 ^ (t1 >>> 1);
        return ((t12 >>> 2) ^ t0) ^ (t12 >>> 5);
    }

    private static int mcol(int x) {
        int t0 = shift(x, 8);
        int t1 = x ^ t0;
        return (shift(t1, 16) ^ t0) ^ FFmulX(t1);
    }

    private static int inv_mcol(int x) {
        int t1 = x ^ shift(x, 8);
        int t0 = x ^ FFmulX(t1);
        int t12 = t1 ^ FFmulX2(t0);
        return t0 ^ (shift(t12, 16) ^ t12);
    }

    private static int subWord(int x) {
        return (S[x & GF2Field.MASK] & 255) | ((S[(x >> 8) & GF2Field.MASK] & 255) << 8) | ((S[(x >> 16) & GF2Field.MASK] & 255) << 16) | (S[(x >> 24) & GF2Field.MASK] << 24);
    }

    private int[][] generateWorkingKey(byte[] key, boolean forEncryption2) {
        int keyLen = key.length;
        if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0) {
            throw new IllegalArgumentException("Key length not 128/192/256 bits.");
        }
        int KC = keyLen >>> 2;
        this.ROUNDS = KC + 6;
        int[][] W = (int[][]) Array.newInstance(Integer.TYPE, this.ROUNDS + 1, 4);
        switch (KC) {
            case 4:
                int col0 = Pack.littleEndianToInt(key, 0);
                W[0][0] = col0;
                int col1 = Pack.littleEndianToInt(key, 4);
                W[0][1] = col1;
                int col2 = Pack.littleEndianToInt(key, 8);
                W[0][2] = col2;
                int col3 = Pack.littleEndianToInt(key, 12);
                W[0][3] = col3;
                for (int i = 1; i <= 10; i++) {
                    col0 ^= subWord(shift(col3, 8)) ^ rcon[i - 1];
                    W[i][0] = col0;
                    col1 ^= col0;
                    W[i][1] = col1;
                    col2 ^= col1;
                    W[i][2] = col2;
                    col3 ^= col2;
                    W[i][3] = col3;
                }
                break;
            case 5:
            case 7:
            default:
                throw new IllegalStateException("Should never get here");
            case 6:
                int col02 = Pack.littleEndianToInt(key, 0);
                W[0][0] = col02;
                int col12 = Pack.littleEndianToInt(key, 4);
                W[0][1] = col12;
                int col22 = Pack.littleEndianToInt(key, 8);
                W[0][2] = col22;
                int col32 = Pack.littleEndianToInt(key, 12);
                W[0][3] = col32;
                int col4 = Pack.littleEndianToInt(key, 16);
                int col5 = Pack.littleEndianToInt(key, 20);
                int i2 = 1;
                int rcon2 = 1;
                while (true) {
                    W[i2][0] = col4;
                    W[i2][1] = col5;
                    int colx = subWord(shift(col5, 8)) ^ rcon2;
                    int rcon3 = rcon2 << 1;
                    int col03 = col02 ^ colx;
                    W[i2][2] = col03;
                    int col13 = col12 ^ col03;
                    W[i2][3] = col13;
                    int col23 = col22 ^ col13;
                    W[i2 + 1][0] = col23;
                    int col33 = col32 ^ col23;
                    W[i2 + 1][1] = col33;
                    int col42 = col4 ^ col33;
                    W[i2 + 1][2] = col42;
                    int col52 = col5 ^ col42;
                    W[i2 + 1][3] = col52;
                    int colx2 = subWord(shift(col52, 8)) ^ rcon3;
                    rcon2 = rcon3 << 1;
                    col02 = col03 ^ colx2;
                    W[i2 + 2][0] = col02;
                    col12 = col13 ^ col02;
                    W[i2 + 2][1] = col12;
                    col22 = col23 ^ col12;
                    W[i2 + 2][2] = col22;
                    col32 = col33 ^ col22;
                    W[i2 + 2][3] = col32;
                    i2 += 3;
                    if (i2 >= 13) {
                        break;
                    } else {
                        col4 = col42 ^ col32;
                        col5 = col52 ^ col4;
                    }
                }
            case 8:
                int col04 = Pack.littleEndianToInt(key, 0);
                W[0][0] = col04;
                int col14 = Pack.littleEndianToInt(key, 4);
                W[0][1] = col14;
                int col24 = Pack.littleEndianToInt(key, 8);
                W[0][2] = col24;
                int col34 = Pack.littleEndianToInt(key, 12);
                W[0][3] = col34;
                int col43 = Pack.littleEndianToInt(key, 16);
                W[1][0] = col43;
                int col53 = Pack.littleEndianToInt(key, 20);
                W[1][1] = col53;
                int col6 = Pack.littleEndianToInt(key, 24);
                W[1][2] = col6;
                int col7 = Pack.littleEndianToInt(key, 28);
                W[1][3] = col7;
                int i3 = 2;
                int rcon4 = 1;
                while (true) {
                    int colx3 = subWord(shift(col7, 8)) ^ rcon4;
                    rcon4 <<= 1;
                    col04 ^= colx3;
                    W[i3][0] = col04;
                    col14 ^= col04;
                    W[i3][1] = col14;
                    col24 ^= col14;
                    W[i3][2] = col24;
                    col34 ^= col24;
                    W[i3][3] = col34;
                    int i4 = i3 + 1;
                    if (i4 >= 15) {
                        break;
                    } else {
                        col43 ^= subWord(col34);
                        W[i4][0] = col43;
                        col53 ^= col43;
                        W[i4][1] = col53;
                        col6 ^= col53;
                        W[i4][2] = col6;
                        col7 ^= col6;
                        W[i4][3] = col7;
                        i3 = i4 + 1;
                    }
                }
        }
        if (!forEncryption2) {
            for (int j = 1; j < this.ROUNDS; j++) {
                for (int i5 = 0; i5 < 4; i5++) {
                    W[j][i5] = inv_mcol(W[j][i5]);
                }
            }
        }
        return W;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean forEncryption2, CipherParameters params) {
        if (params instanceof KeyParameter) {
            this.WorkingKey = generateWorkingKey(((KeyParameter) params).getKey(), forEncryption2);
            this.forEncryption = forEncryption2;
            return;
        }
        throw new IllegalArgumentException("invalid parameter passed to AES init - " + params.getClass().getName());
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "AES";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        if (this.WorkingKey == null) {
            throw new IllegalStateException("AES engine not initialised");
        } else if (inOff > in.length - 16) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff > out.length - 16) {
            throw new OutputLengthException("output buffer too short");
        } else if (this.forEncryption) {
            encryptBlock(in, inOff, out, outOff, this.WorkingKey);
            return 16;
        } else {
            decryptBlock(in, inOff, out, outOff, this.WorkingKey);
            return 16;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
    }

    private void encryptBlock(byte[] in, int inOff, byte[] out, int outOff, int[][] KW) {
        int C0 = Pack.littleEndianToInt(in, inOff + 0);
        int C1 = Pack.littleEndianToInt(in, inOff + 4);
        int C2 = Pack.littleEndianToInt(in, inOff + 8);
        int C3 = Pack.littleEndianToInt(in, inOff + 12);
        int t0 = C0 ^ KW[0][0];
        int t1 = C1 ^ KW[0][1];
        int t2 = C2 ^ KW[0][2];
        int r = 1;
        int r3 = C3 ^ KW[0][3];
        while (r < this.ROUNDS - 1) {
            int r0 = mcol((((S[t0 & GF2Field.MASK] & 255) ^ ((S[(t1 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(t2 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(r3 >> 24) & GF2Field.MASK] << 24)) ^ KW[r][0];
            int r1 = mcol((((S[t1 & GF2Field.MASK] & 255) ^ ((S[(t2 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(r3 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(t0 >> 24) & GF2Field.MASK] << 24)) ^ KW[r][1];
            int r2 = mcol((((S[t2 & GF2Field.MASK] & 255) ^ ((S[(r3 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(t0 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(t1 >> 24) & GF2Field.MASK] << 24)) ^ KW[r][2];
            int r4 = r + 1;
            int r32 = mcol((((S[r3 & GF2Field.MASK] & 255) ^ ((S[(t0 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(t1 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(t2 >> 24) & GF2Field.MASK] << 24)) ^ KW[r][3];
            t0 = mcol((((S[r0 & GF2Field.MASK] & 255) ^ ((S[(r1 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(r2 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(r32 >> 24) & GF2Field.MASK] << 24)) ^ KW[r4][0];
            t1 = mcol((((S[r1 & GF2Field.MASK] & 255) ^ ((S[(r2 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(r32 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(r0 >> 24) & GF2Field.MASK] << 24)) ^ KW[r4][1];
            t2 = mcol((((S[r2 & GF2Field.MASK] & 255) ^ ((S[(r32 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(r0 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(r1 >> 24) & GF2Field.MASK] << 24)) ^ KW[r4][2];
            r = r4 + 1;
            r3 = mcol((((S[r32 & GF2Field.MASK] & 255) ^ ((S[(r0 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(r1 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(r2 >> 24) & GF2Field.MASK] << 24)) ^ KW[r4][3];
        }
        int r02 = mcol((((S[t0 & GF2Field.MASK] & 255) ^ ((S[(t1 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(t2 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(r3 >> 24) & GF2Field.MASK] << 24)) ^ KW[r][0];
        int r12 = mcol((((S[t1 & GF2Field.MASK] & 255) ^ ((S[(t2 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(r3 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(t0 >> 24) & GF2Field.MASK] << 24)) ^ KW[r][1];
        int r22 = mcol((((S[t2 & GF2Field.MASK] & 255) ^ ((S[(r3 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(t0 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(t1 >> 24) & GF2Field.MASK] << 24)) ^ KW[r][2];
        int r5 = r + 1;
        int r33 = mcol((((S[r3 & GF2Field.MASK] & 255) ^ ((S[(t0 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(t1 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(t2 >> 24) & GF2Field.MASK] << 24)) ^ KW[r][3];
        int C02 = ((((S[r02 & GF2Field.MASK] & 255) ^ ((S[(r12 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(r22 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(r33 >> 24) & GF2Field.MASK] << 24)) ^ KW[r5][0];
        int C12 = ((((S[r12 & GF2Field.MASK] & 255) ^ ((S[(r22 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(r33 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(r02 >> 24) & GF2Field.MASK] << 24)) ^ KW[r5][1];
        int C22 = ((((S[r22 & GF2Field.MASK] & 255) ^ ((S[(r33 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(r02 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(r12 >> 24) & GF2Field.MASK] << 24)) ^ KW[r5][2];
        int C32 = ((((S[r33 & GF2Field.MASK] & 255) ^ ((S[(r02 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((S[(r12 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (S[(r22 >> 24) & GF2Field.MASK] << 24)) ^ KW[r5][3];
        Pack.intToLittleEndian(C02, out, outOff + 0);
        Pack.intToLittleEndian(C12, out, outOff + 4);
        Pack.intToLittleEndian(C22, out, outOff + 8);
        Pack.intToLittleEndian(C32, out, outOff + 12);
    }

    private void decryptBlock(byte[] in, int inOff, byte[] out, int outOff, int[][] KW) {
        int C0 = Pack.littleEndianToInt(in, inOff + 0);
        int C1 = Pack.littleEndianToInt(in, inOff + 4);
        int C2 = Pack.littleEndianToInt(in, inOff + 8);
        int C3 = Pack.littleEndianToInt(in, inOff + 12);
        int t0 = C0 ^ KW[this.ROUNDS][0];
        int t1 = C1 ^ KW[this.ROUNDS][1];
        int t2 = C2 ^ KW[this.ROUNDS][2];
        int r = this.ROUNDS - 1;
        int r3 = C3 ^ KW[this.ROUNDS][3];
        int r2 = r;
        while (r2 > 1) {
            int r0 = inv_mcol((((Si[t0 & GF2Field.MASK] & 255) ^ ((Si[(r3 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(t2 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(t1 >> 24) & GF2Field.MASK] << 24)) ^ KW[r2][0];
            int r1 = inv_mcol((((Si[t1 & GF2Field.MASK] & 255) ^ ((Si[(t0 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(r3 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(t2 >> 24) & GF2Field.MASK] << 24)) ^ KW[r2][1];
            int r22 = inv_mcol((((Si[t2 & GF2Field.MASK] & 255) ^ ((Si[(t1 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(t0 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(r3 >> 24) & GF2Field.MASK] << 24)) ^ KW[r2][2];
            int r4 = r2 - 1;
            int r32 = inv_mcol((((Si[r3 & GF2Field.MASK] & 255) ^ ((Si[(t2 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(t1 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(t0 >> 24) & GF2Field.MASK] << 24)) ^ KW[r2][3];
            t0 = inv_mcol((((Si[r0 & GF2Field.MASK] & 255) ^ ((Si[(r32 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(r22 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(r1 >> 24) & GF2Field.MASK] << 24)) ^ KW[r4][0];
            t1 = inv_mcol((((Si[r1 & GF2Field.MASK] & 255) ^ ((Si[(r0 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(r32 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(r22 >> 24) & GF2Field.MASK] << 24)) ^ KW[r4][1];
            t2 = inv_mcol((((Si[r22 & GF2Field.MASK] & 255) ^ ((Si[(r1 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(r0 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(r32 >> 24) & GF2Field.MASK] << 24)) ^ KW[r4][2];
            r2 = r4 - 1;
            r3 = inv_mcol((((Si[r32 & GF2Field.MASK] & 255) ^ ((Si[(r22 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(r1 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(r0 >> 24) & GF2Field.MASK] << 24)) ^ KW[r4][3];
        }
        int r02 = inv_mcol((((Si[t0 & GF2Field.MASK] & 255) ^ ((Si[(r3 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(t2 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(t1 >> 24) & GF2Field.MASK] << 24)) ^ KW[r2][0];
        int r12 = inv_mcol((((Si[t1 & GF2Field.MASK] & 255) ^ ((Si[(t0 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(r3 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(t2 >> 24) & GF2Field.MASK] << 24)) ^ KW[r2][1];
        int r23 = inv_mcol((((Si[t2 & GF2Field.MASK] & 255) ^ ((Si[(t1 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(t0 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(r3 >> 24) & GF2Field.MASK] << 24)) ^ KW[r2][2];
        int r33 = inv_mcol((((Si[r3 & GF2Field.MASK] & 255) ^ ((Si[(t2 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(t1 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(t0 >> 24) & GF2Field.MASK] << 24)) ^ KW[r2][3];
        int C02 = ((((Si[r02 & GF2Field.MASK] & 255) ^ ((Si[(r33 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(r23 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(r12 >> 24) & GF2Field.MASK] << 24)) ^ KW[0][0];
        int C12 = ((((Si[r12 & GF2Field.MASK] & 255) ^ ((Si[(r02 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(r33 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(r23 >> 24) & GF2Field.MASK] << 24)) ^ KW[0][1];
        int C22 = ((((Si[r23 & GF2Field.MASK] & 255) ^ ((Si[(r12 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(r02 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(r33 >> 24) & GF2Field.MASK] << 24)) ^ KW[0][2];
        int C32 = ((((Si[r33 & GF2Field.MASK] & 255) ^ ((Si[(r23 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((Si[(r12 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (Si[(r02 >> 24) & GF2Field.MASK] << 24)) ^ KW[0][3];
        Pack.intToLittleEndian(C02, out, outOff + 0);
        Pack.intToLittleEndian(C12, out, outOff + 4);
        Pack.intToLittleEndian(C22, out, outOff + 8);
        Pack.intToLittleEndian(C32, out, outOff + 12);
    }

    @Override // com.mi.car.jsse.easysec.crypto.StatelessProcessing
    public BlockCipher newInstance() {
        return new AESLightEngine();
    }
}
