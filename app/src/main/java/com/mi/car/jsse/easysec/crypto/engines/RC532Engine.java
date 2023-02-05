package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.RC5Parameters;

public class RC532Engine implements BlockCipher {
    private static final int P32 = -1209970333;
    private static final int Q32 = -1640531527;
    private int[] _S = null;
    private int _noRounds = 12;
    private boolean forEncryption;

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "RC5-32";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean forEncryption2, CipherParameters params) {
        if (params instanceof RC5Parameters) {
            RC5Parameters p = (RC5Parameters) params;
            this._noRounds = p.getRounds();
            setKey(p.getKey());
        } else if (params instanceof KeyParameter) {
            setKey(((KeyParameter) params).getKey());
        } else {
            throw new IllegalArgumentException("invalid parameter passed to RC532 init - " + params.getClass().getName());
        }
        this.forEncryption = forEncryption2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        if (this.forEncryption) {
            return encryptBlock(in, inOff, out, outOff);
        }
        return decryptBlock(in, inOff, out, outOff);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
    }

    private void setKey(byte[] key) {
        int iter;
        int[] L = new int[((key.length + 3) / 4)];
        for (int i = 0; i != key.length; i++) {
            int i2 = i / 4;
            L[i2] = L[i2] + ((key[i] & 255) << ((i % 4) * 8));
        }
        this._S = new int[((this._noRounds + 1) * 2)];
        this._S[0] = P32;
        for (int i3 = 1; i3 < this._S.length; i3++) {
            this._S[i3] = this._S[i3 - 1] + Q32;
        }
        if (L.length > this._S.length) {
            iter = L.length * 3;
        } else {
            iter = this._S.length * 3;
        }
        int A = 0;
        int B = 0;
        int i4 = 0;
        int j = 0;
        for (int k = 0; k < iter; k++) {
            int[] iArr = this._S;
            A = rotateLeft(this._S[i4] + A + B, 3);
            iArr[i4] = A;
            B = rotateLeft(L[j] + A + B, A + B);
            L[j] = B;
            i4 = (i4 + 1) % this._S.length;
            j = (j + 1) % L.length;
        }
    }

    private int encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int A = bytesToWord(in, inOff) + this._S[0];
        int B = bytesToWord(in, inOff + 4) + this._S[1];
        for (int i = 1; i <= this._noRounds; i++) {
            A = rotateLeft(A ^ B, B) + this._S[i * 2];
            B = rotateLeft(B ^ A, A) + this._S[(i * 2) + 1];
        }
        wordToBytes(A, out, outOff);
        wordToBytes(B, out, outOff + 4);
        return 8;
    }

    private int decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int A = bytesToWord(in, inOff);
        int B = bytesToWord(in, inOff + 4);
        for (int i = this._noRounds; i >= 1; i--) {
            B = rotateRight(B - this._S[(i * 2) + 1], A) ^ A;
            A = rotateRight(A - this._S[i * 2], B) ^ B;
        }
        wordToBytes(A - this._S[0], out, outOff);
        wordToBytes(B - this._S[1], out, outOff + 4);
        return 8;
    }

    private int rotateLeft(int x, int y) {
        return (x << (y & 31)) | (x >>> (32 - (y & 31)));
    }

    private int rotateRight(int x, int y) {
        return (x >>> (y & 31)) | (x << (32 - (y & 31)));
    }

    private int bytesToWord(byte[] src, int srcOff) {
        return (src[srcOff] & 255) | ((src[srcOff + 1] & 255) << 8) | ((src[srcOff + 2] & 255) << 16) | ((src[srcOff + 3] & 255) << 24);
    }

    private void wordToBytes(int word, byte[] dst, int dstOff) {
        dst[dstOff] = (byte) word;
        dst[dstOff + 1] = (byte) (word >> 8);
        dst[dstOff + 2] = (byte) (word >> 16);
        dst[dstOff + 3] = (byte) (word >> 24);
    }
}
