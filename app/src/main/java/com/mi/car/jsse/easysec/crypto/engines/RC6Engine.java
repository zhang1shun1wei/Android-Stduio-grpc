package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;

public class RC6Engine implements BlockCipher {
    private static final int LGW = 5;
    private static final int P32 = -1209970333;
    private static final int Q32 = -1640531527;
    private static final int _noRounds = 20;
    private static final int bytesPerWord = 4;
    private static final int wordSize = 32;
    private int[] _S = null;
    private boolean forEncryption;

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "RC6";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean forEncryption2, CipherParameters params) {
        if (!(params instanceof KeyParameter)) {
            throw new IllegalArgumentException("invalid parameter passed to RC6 init - " + params.getClass().getName());
        }
        this.forEncryption = forEncryption2;
        setKey(((KeyParameter) params).getKey());
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int blockSize = getBlockSize();
        if (this._S == null) {
            throw new IllegalStateException("RC6 engine not initialised");
        } else if (inOff + blockSize > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff + blockSize > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else if (this.forEncryption) {
            return encryptBlock(in, inOff, out, outOff);
        } else {
            return decryptBlock(in, inOff, out, outOff);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
    }

    private void setKey(byte[] key) {
        int iter;
        if ((key.length + 3) / 4 == 0) {
        }
        int[] L = new int[(((key.length + 4) - 1) / 4)];
        for (int i = key.length - 1; i >= 0; i--) {
            L[i / 4] = (L[i / 4] << 8) + (key[i] & 255);
        }
        this._S = new int[44];
        this._S[0] = P32;
        for (int i2 = 1; i2 < this._S.length; i2++) {
            this._S[i2] = this._S[i2 - 1] + Q32;
        }
        if (L.length > this._S.length) {
            iter = L.length * 3;
        } else {
            iter = this._S.length * 3;
        }
        int A = 0;
        int B = 0;
        int i3 = 0;
        int j = 0;
        for (int k = 0; k < iter; k++) {
            int[] iArr = this._S;
            A = rotateLeft(this._S[i3] + A + B, 3);
            iArr[i3] = A;
            B = rotateLeft(L[j] + A + B, A + B);
            L[j] = B;
            i3 = (i3 + 1) % this._S.length;
            j = (j + 1) % L.length;
        }
    }

    private int encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int A = bytesToWord(in, inOff);
        int B = bytesToWord(in, inOff + 4);
        int C = bytesToWord(in, inOff + 8);
        int D = bytesToWord(in, inOff + 12);
        int B2 = B + this._S[0];
        int D2 = D + this._S[1];
        for (int i = 1; i <= 20; i++) {
            int t = rotateLeft(B2 * ((B2 * 2) + 1), 5);
            int u = rotateLeft(D2 * ((D2 * 2) + 1), 5);
            int A2 = rotateLeft(A ^ t, u) + this._S[i * 2];
            A = B2;
            B2 = rotateLeft(C ^ u, t) + this._S[(i * 2) + 1];
            C = D2;
            D2 = A2;
        }
        int A3 = A + this._S[42];
        int C2 = C + this._S[43];
        wordToBytes(A3, out, outOff);
        wordToBytes(B2, out, outOff + 4);
        wordToBytes(C2, out, outOff + 8);
        wordToBytes(D2, out, outOff + 12);
        return 16;
    }

    private int decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int A = bytesToWord(in, inOff);
        int B = bytesToWord(in, inOff + 4);
        int C = bytesToWord(in, inOff + 8);
        int D = bytesToWord(in, inOff + 12);
        int C2 = C - this._S[43];
        int A2 = A - this._S[42];
        for (int i = 20; i >= 1; i--) {
            D = C2;
            B = A2;
            int t = rotateLeft(B * ((B * 2) + 1), 5);
            int u = rotateLeft(D * ((D * 2) + 1), 5);
            C2 = rotateRight(B - this._S[(i * 2) + 1], t) ^ u;
            A2 = rotateRight(D - this._S[i * 2], u) ^ t;
        }
        int D2 = D - this._S[1];
        wordToBytes(A2, out, outOff);
        wordToBytes(B - this._S[0], out, outOff + 4);
        wordToBytes(C2, out, outOff + 8);
        wordToBytes(D2, out, outOff + 12);
        return 16;
    }

    private int rotateLeft(int x, int y) {
        return (x << y) | (x >>> (-y));
    }

    private int rotateRight(int x, int y) {
        return (x >>> y) | (x << (-y));
    }

    private int bytesToWord(byte[] src, int srcOff) {
        int word = 0;
        for (int i = 3; i >= 0; i--) {
            word = (word << 8) + (src[i + srcOff] & 255);
        }
        return word;
    }

    private void wordToBytes(int word, byte[] dst, int dstOff) {
        for (int i = 0; i < 4; i++) {
            dst[i + dstOff] = (byte) word;
            word >>>= 8;
        }
    }
}
