package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.math.ec.Tnaf;
import com.mi.car.jsse.easysec.util.Arrays;

public class GOST3412_2015Engine implements BlockCipher {
    protected static final int BLOCK_SIZE = 16;
    private static final byte[] PI = {-4, -18, -35, 17, -49, 110, 49, 22, -5, -60, -6, -38, 35, -59, 4, 77, -23, 119, -16, -37, -109, 46, -103, -70, 23, 54, -15, -69, 20, -51, 95, -63, -7, 24, 101, 90, -30, 92, -17, 33, -127, 28, 60, 66, -117, 1, -114, 79, 5, -124, 2, -82, -29, 106, -113, -96, 6, 11, -19, -104, Byte.MAX_VALUE, -44, -45, 31, -21, 52, 44, 81, -22, -56, 72, -85, -14, 42, 104, -94, -3, 58, -50, -52, -75, 112, 14, 86, 8, 12, 118, 18, -65, 114, 19, 71, -100, -73, 93, -121, 21, -95, -106, 41, Tnaf.POW_2_WIDTH, 123, -102, -57, -13, -111, 120, 111, -99, -98, -78, -79, 50, 117, 25, 61, -1, 53, -118, 126, 109, 84, -58, Byte.MIN_VALUE, -61, -67, 13, 87, -33, -11, 36, -87, 62, -88, 67, -55, -41, 121, -42, -10, 124, 34, -71, 3, -32, 15, -20, -34, 122, -108, -80, PSSSigner.TRAILER_IMPLICIT, -36, -24, 40, 80, 78, 51, 10, 74, -89, -105, 96, 115, 30, 0, 98, 68, 26, -72, 56, -126, 100, -97, 38, 65, -83, 69, 70, -110, 39, 94, 85, 47, -116, -93, -91, 125, 105, -43, -107, 59, 7, 88, -77, 64, -122, -84, 29, -9, 48, 55, 107, -28, -120, -39, -25, -119, -31, 27, -125, 73, 76, 63, -8, -2, -115, 83, -86, -112, -54, -40, -123, 97, 32, 113, 103, -92, 45, 43, 9, 91, -53, -101, 37, -48, -66, -27, 108, 82, 89, -90, 116, -46, -26, -12, -76, -64, -47, 102, -81, -62, 57, 75, 99, -74};
    private static final byte[] inversePI = {-91, 45, 50, -113, 14, 48, 56, -64, 84, -26, -98, 57, 85, 126, 82, -111, 100, 3, 87, 90, 28, 96, 7, 24, 33, 114, -88, -47, 41, -58, -92, 63, -32, 39, -115, 12, -126, -22, -82, -76, -102, 99, 73, -27, 66, -28, 21, -73, -56, 6, 112, -99, 65, 117, 25, -55, -86, -4, 77, -65, 42, 115, -124, -43, -61, -81, 43, -122, -89, -79, -78, 91, 70, -45, -97, -3, -44, 15, -100, 47, -101, 67, -17, -39, 121, -74, 83, Byte.MAX_VALUE, -63, -16, 35, -25, 37, 94, -75, 30, -94, -33, -90, -2, -84, 34, -7, -30, 74, PSSSigner.TRAILER_IMPLICIT, 53, -54, -18, 120, 5, 107, 81, -31, 89, -93, -14, 113, 86, 17, 106, -119, -108, 101, -116, -69, 119, 60, 123, 40, -85, -46, 49, -34, -60, 95, -52, -49, 118, 44, -72, -40, 46, 54, -37, 105, -77, 20, -107, -66, 98, -95, 59, 22, 102, -23, 92, 108, 109, -83, 55, 97, 75, -71, -29, -70, -15, -96, -123, -125, -38, 71, -59, -80, 51, -6, -106, 111, 110, -62, -10, 80, -1, 93, -87, -114, 23, 27, -105, 125, -20, 88, -9, 31, -5, 124, 9, 13, 122, 103, 69, -121, -36, -24, 79, 29, 78, 4, -21, -8, -13, 62, 61, -67, -118, -120, -35, -51, 11, 19, -104, 2, -109, Byte.MIN_VALUE, -112, -48, 36, 52, -53, -19, -12, -50, -103, Tnaf.POW_2_WIDTH, 68, 64, -110, 58, 1, 38, 18, 26, 72, 104, -11, -127, -117, -57, -42, 32, 10, 8, 0, 76, -41, 116};
    private int KEY_LENGTH = 32;
    private int SUB_LENGTH = (this.KEY_LENGTH / 2);
    private byte[][] _gf_mul = init_gf256_mul_table();
    private boolean forEncryption;
    private final byte[] lFactors = {-108, 32, -123, Tnaf.POW_2_WIDTH, -62, -64, 1, -5, 1, -64, -62, Tnaf.POW_2_WIDTH, -123, 32, -108, 1};
    private byte[][] subKeys = null;

    private static byte[][] init_gf256_mul_table() {
        byte[][] mul_table = new byte[256][];
        for (int x = 0; x < 256; x++) {
            mul_table[x] = new byte[256];
            for (int y = 0; y < 256; y++) {
                mul_table[x][y] = kuz_mul_gf256_slow((byte) x, (byte) y);
            }
        }
        return mul_table;
    }

    private static byte kuz_mul_gf256_slow(byte a, byte b) {
        byte p = 0;
        for (byte counter = 0; counter < 8 && a != 0 && b != 0; counter = (byte) (counter + 1)) {
            if ((b & 1) != 0) {
                p = (byte) (p ^ a);
            }
            byte hi_bit_set = (byte) (a & 128);
            a = (byte) (a << 1);
            if (hi_bit_set != 0) {
                a = (byte) (a ^ 195);
            }
            b = (byte) (b >> 1);
        }
        return p;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "GOST3412_2015";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean forEncryption2, CipherParameters params) throws IllegalArgumentException {
        if (params instanceof KeyParameter) {
            this.forEncryption = forEncryption2;
            generateSubKeys(((KeyParameter) params).getKey());
        } else if (params != null) {
            throw new IllegalArgumentException("invalid parameter passed to GOST3412_2015 init - " + params.getClass().getName());
        }
    }

    private void generateSubKeys(byte[] userKey) {
        if (userKey.length != this.KEY_LENGTH) {
            throw new IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!");
        }
        this.subKeys = new byte[10][];
        for (int i = 0; i < 10; i++) {
            this.subKeys[i] = new byte[this.SUB_LENGTH];
        }
        byte[] x = new byte[this.SUB_LENGTH];
        byte[] y = new byte[this.SUB_LENGTH];
        for (int i2 = 0; i2 < this.SUB_LENGTH; i2++) {
            byte[] bArr = this.subKeys[0];
            byte b = userKey[i2];
            x[i2] = b;
            bArr[i2] = b;
            byte[] bArr2 = this.subKeys[1];
            byte b2 = userKey[this.SUB_LENGTH + i2];
            y[i2] = b2;
            bArr2[i2] = b2;
        }
        byte[] c = new byte[this.SUB_LENGTH];
        for (int k = 1; k < 5; k++) {
            for (int j = 1; j <= 8; j++) {
                C(c, ((k - 1) * 8) + j);
                F(c, x, y);
            }
            System.arraycopy(x, 0, this.subKeys[k * 2], 0, this.SUB_LENGTH);
            System.arraycopy(y, 0, this.subKeys[(k * 2) + 1], 0, this.SUB_LENGTH);
        }
    }

    private void C(byte[] c, int i) {
        Arrays.clear(c);
        c[15] = (byte) i;
        L(c);
    }

    private void F(byte[] k, byte[] a1, byte[] a0) {
        byte[] temp = LSX(k, a1);
        X(temp, a0);
        System.arraycopy(a1, 0, a0, 0, this.SUB_LENGTH);
        System.arraycopy(temp, 0, a1, 0, this.SUB_LENGTH);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.subKeys == null) {
            throw new IllegalStateException("GOST3412_2015 engine not initialised");
        } else if (inOff + 16 > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff + 16 > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            GOST3412_2015Func(in, inOff, out, outOff);
            return 16;
        }
    }

    private void GOST3412_2015Func(byte[] in, int inOff, byte[] out, int outOff) {
        byte[] block = new byte[16];
        System.arraycopy(in, inOff, block, 0, 16);
        if (this.forEncryption) {
            for (int i = 0; i < 9; i++) {
                block = Arrays.copyOf(LSX(this.subKeys[i], block), 16);
            }
            X(block, this.subKeys[9]);
        } else {
            for (int i2 = 9; i2 > 0; i2--) {
                block = Arrays.copyOf(XSL(this.subKeys[i2], block), 16);
            }
            X(block, this.subKeys[0]);
        }
        System.arraycopy(block, 0, out, outOff, 16);
    }

    private byte[] LSX(byte[] k, byte[] a) {
        byte[] result = Arrays.copyOf(k, k.length);
        X(result, a);
        S(result);
        L(result);
        return result;
    }

    private byte[] XSL(byte[] k, byte[] a) {
        byte[] result = Arrays.copyOf(k, k.length);
        X(result, a);
        inverseL(result);
        inverseS(result);
        return result;
    }

    private void X(byte[] result, byte[] data) {
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (result[i] ^ data[i]);
        }
    }

    private void S(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            data[i] = PI[unsignedByte(data[i])];
        }
    }

    private void inverseS(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            data[i] = inversePI[unsignedByte(data[i])];
        }
    }

    private int unsignedByte(byte b) {
        return b & 255;
    }

    private void L(byte[] data) {
        for (int i = 0; i < 16; i++) {
            R(data);
        }
    }

    private void inverseL(byte[] data) {
        for (int i = 0; i < 16; i++) {
            inverseR(data);
        }
    }

    private void R(byte[] data) {
        byte z = l(data);
        System.arraycopy(data, 0, data, 1, 15);
        data[0] = z;
    }

    private void inverseR(byte[] data) {
        byte[] temp = new byte[16];
        System.arraycopy(data, 1, temp, 0, 15);
        temp[15] = data[0];
        byte z = l(temp);
        System.arraycopy(data, 1, data, 0, 15);
        data[15] = z;
    }

    private byte l(byte[] data) {
        byte x = data[15];
        for (int i = 14; i >= 0; i--) {
            x = (byte) (this._gf_mul[unsignedByte(data[i])][unsignedByte(this.lFactors[i])] ^ x);
        }
        return x;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
    }
}
