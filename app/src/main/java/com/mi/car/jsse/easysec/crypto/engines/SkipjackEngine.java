package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;

public class SkipjackEngine implements BlockCipher {
    static final int BLOCK_SIZE = 8;
    static short[] ftable = {163, 215, 9, 131, 248, 72, 246, 244, 179, 33, 21, 120, 153, 177, 175, 249, 231, 45, 77, 138, 206, 76, 202, 46, 82, 149, 217, 30, 78, 56, 68, 40, 10, 223, 2, 160, 23, 241, 96, 104, 18, 183, 122, 195, 233, 250, 61, 83, 150, 132, 107, 186, 242, 99, 154, 25, 124, 174, 229, 245, 247, 22, 106, 162, 57, 182, 123, 15, 193, 147, 129, 27, 238, 180, 26, 234, 208, 145, 47, 184, 85, 185, 218, 133, 63, 65, 191, 224, 90, 88, 128, 95, 102, 11, 216, 144, 53, 213, 192, 167, 51, 6, 101, 105, 69, 0, 148, 86, 109, 152, 155, 118, 151, 252, 178, 194, 176, 254, 219, 32, 225, 235, 214, 228, 221, 71, 74, 29, 66, 237, 158, 110, 73, 60, 205, 67, 39, 210, 7, 212, 222, 199, 103, 24, 137, 203, 48, 31, 141, 198, 143, 170, 200, 116, 220, 201, 93, 92, 49, 164, 112, 136, 97, 44, 159, 13, 43, 135, 80, 130, 84, 100, 38, 125, 3, 64, 52, 75, 28, 115, 209, 196, 253, 59, 204, 251, 127, 171, 230, 62, 91, 165, 173, 4, 35, 156, 20, 81, 34, 240, 41, 121, 113, 126, 255, 140, 14, 226, 12, 239, 188, 114, 117, 111, 55, 161, 236, 211, 142, 98, 139, 134, 16, 232, 8, 119, 17, 190, 146, 79, 36, 197, 50, 54, 157, 207, 243, 166, 187, 172, 94, 108, 169, 19, 87, 37, 181, 227, 189, 168, 58, 1, 5, 89, 42, 70};
    private boolean encrypting;
    private int[] key0;
    private int[] key1;
    private int[] key2;
    private int[] key3;

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean encrypting2, CipherParameters params) {
        if (!(params instanceof KeyParameter)) {
            throw new IllegalArgumentException("invalid parameter passed to SKIPJACK init - " + params.getClass().getName());
        }
        byte[] keyBytes = ((KeyParameter) params).getKey();
        this.encrypting = encrypting2;
        this.key0 = new int[32];
        this.key1 = new int[32];
        this.key2 = new int[32];
        this.key3 = new int[32];
        for (int i = 0; i < 32; i++) {
            this.key0[i] = keyBytes[(i * 4) % 10] & 255;
            this.key1[i] = keyBytes[((i * 4) + 1) % 10] & 255;
            this.key2[i] = keyBytes[((i * 4) + 2) % 10] & 255;
            this.key3[i] = keyBytes[((i * 4) + 3) % 10] & 255;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "SKIPJACK";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        if (this.key1 == null) {
            throw new IllegalStateException("SKIPJACK engine not initialised");
        } else if (inOff + 8 > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff + 8 > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else if (this.encrypting) {
            encryptBlock(in, inOff, out, outOff);
            return 8;
        } else {
            decryptBlock(in, inOff, out, outOff);
            return 8;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
    }

    private int g(int k, int w) {
        int g1 = (w >> 8) & GF2Field.MASK;
        int g2 = w & GF2Field.MASK;
        int g3 = ftable[this.key0[k] ^ g2] ^ g1;
        int g4 = ftable[this.key1[k] ^ g3] ^ g2;
        int g5 = ftable[this.key2[k] ^ g4] ^ g3;
        return (g5 << 8) + (ftable[this.key3[k] ^ g5] ^ g4);
    }

    public int encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int w1 = (in[inOff + 0] << 8) + (in[inOff + 1] & 255);
        int w2 = (in[inOff + 2] << 8) + (in[inOff + 3] & 255);
        int w3 = (in[inOff + 4] << 8) + (in[inOff + 5] & 255);
        int w4 = (in[inOff + 6] << 8) + (in[inOff + 7] & 255);
        int k = 0;
        for (int t = 0; t < 2; t++) {
            for (int i = 0; i < 8; i++) {
                w4 = w3;
                w3 = w2;
                w2 = g(k, w1);
                w1 = (w2 ^ w4) ^ (k + 1);
                k++;
            }
            for (int i2 = 0; i2 < 8; i2++) {
                w4 = w3;
                w3 = (w1 ^ w2) ^ (k + 1);
                w2 = g(k, w1);
                w1 = w4;
                k++;
            }
        }
        out[outOff + 0] = (byte) (w1 >> 8);
        out[outOff + 1] = (byte) w1;
        out[outOff + 2] = (byte) (w2 >> 8);
        out[outOff + 3] = (byte) w2;
        out[outOff + 4] = (byte) (w3 >> 8);
        out[outOff + 5] = (byte) w3;
        out[outOff + 6] = (byte) (w4 >> 8);
        out[outOff + 7] = (byte) w4;
        return 8;
    }

    private int h(int k, int w) {
        int h1 = w & GF2Field.MASK;
        int h2 = (w >> 8) & GF2Field.MASK;
        int h3 = ftable[this.key3[k] ^ h2] ^ h1;
        int h4 = ftable[this.key2[k] ^ h3] ^ h2;
        int h5 = ftable[this.key1[k] ^ h4] ^ h3;
        return ((ftable[this.key0[k] ^ h5] ^ h4) << 8) + h5;
    }

    public int decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int w2 = (in[inOff + 0] << 8) + (in[inOff + 1] & 255);
        int w1 = (in[inOff + 2] << 8) + (in[inOff + 3] & 255);
        int w4 = (in[inOff + 4] << 8) + (in[inOff + 5] & 255);
        int w3 = (in[inOff + 6] << 8) + (in[inOff + 7] & 255);
        int k = 31;
        for (int t = 0; t < 2; t++) {
            for (int i = 0; i < 8; i++) {
                w4 = w3;
                w3 = w2;
                w2 = h(k, w1);
                w1 = (w2 ^ w4) ^ (k + 1);
                k--;
            }
            for (int i2 = 0; i2 < 8; i2++) {
                w4 = w3;
                w3 = (w1 ^ w2) ^ (k + 1);
                w2 = h(k, w1);
                w1 = w4;
                k--;
            }
        }
        out[outOff + 0] = (byte) (w2 >> 8);
        out[outOff + 1] = (byte) w2;
        out[outOff + 2] = (byte) (w1 >> 8);
        out[outOff + 3] = (byte) w1;
        out[outOff + 4] = (byte) (w4 >> 8);
        out[outOff + 5] = (byte) w4;
        out[outOff + 6] = (byte) (w3 >> 8);
        out[outOff + 7] = (byte) w3;
        return 8;
    }
}
