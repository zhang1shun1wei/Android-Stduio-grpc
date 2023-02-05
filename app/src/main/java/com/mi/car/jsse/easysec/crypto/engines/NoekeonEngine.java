package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.Pack;

public class NoekeonEngine implements BlockCipher {
    private static final int SIZE = 16;
    private static final byte[] roundConstants = {Byte.MIN_VALUE, 27, 54, 108, -40, -85, 77, -102, 47, 94, PSSSigner.TRAILER_IMPLICIT, 99, -58, -105, 53, 106, -44};
    private boolean _forEncryption;
    private boolean _initialised = false;
    private final int[] k = new int[4];

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "Noekeon";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean forEncryption, CipherParameters params) {
        if (!(params instanceof KeyParameter)) {
            throw new IllegalArgumentException("invalid parameter passed to Noekeon init - " + params.getClass().getName());
        }
        byte[] key = ((KeyParameter) params).getKey();
        if (key.length != 16) {
            throw new IllegalArgumentException("Key length not 128 bits.");
        }
        Pack.bigEndianToInt(key, 0, this.k, 0, 4);
        if (!forEncryption) {
            int a0 = this.k[0];
            int a1 = this.k[1];
            int a2 = this.k[2];
            int a3 = this.k[3];
            int t02 = a0 ^ a2;
            int t022 = t02 ^ (Integers.rotateLeft(t02, 8) ^ Integers.rotateLeft(t02, 24));
            int t13 = a1 ^ a3;
            int t132 = t13 ^ (Integers.rotateLeft(t13, 8) ^ Integers.rotateLeft(t13, 24));
            this.k[0] = a0 ^ t132;
            this.k[1] = a1 ^ t022;
            this.k[2] = a2 ^ t132;
            this.k[3] = a3 ^ t022;
        }
        this._forEncryption = forEncryption;
        this._initialised = true;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        if (!this._initialised) {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        } else if (inOff > in.length - 16) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff <= out.length - 16) {
            return this._forEncryption ? encryptBlock(in, inOff, out, outOff) : decryptBlock(in, inOff, out, outOff);
        } else {
            throw new OutputLengthException("output buffer too short");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
    }

    private int encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int a0 = Pack.bigEndianToInt(in, inOff);
        int a1 = Pack.bigEndianToInt(in, inOff + 4);
        int a2 = Pack.bigEndianToInt(in, inOff + 8);
        int a3 = Pack.bigEndianToInt(in, inOff + 12);
        int k0 = this.k[0];
        int k1 = this.k[1];
        int k2 = this.k[2];
        int k3 = this.k[3];
        int round = 0;
        while (true) {
            int a02 = a0 ^ (roundConstants[round] & 255);
            int t02 = a02 ^ a2;
            int t022 = t02 ^ (Integers.rotateLeft(t02, 8) ^ Integers.rotateLeft(t02, 24));
            int a12 = a1 ^ k1;
            int a32 = a3 ^ k3;
            int t13 = a12 ^ a32;
            int t132 = t13 ^ (Integers.rotateLeft(t13, 8) ^ Integers.rotateLeft(t13, 24));
            int a03 = (a02 ^ k0) ^ t132;
            int a13 = a12 ^ t022;
            int a22 = (a2 ^ k2) ^ t132;
            int a33 = a32 ^ t022;
            round++;
            if (round > 16) {
                Pack.intToBigEndian(a03, out, outOff);
                Pack.intToBigEndian(a13, out, outOff + 4);
                Pack.intToBigEndian(a22, out, outOff + 8);
                Pack.intToBigEndian(a33, out, outOff + 12);
                return 16;
            }
            int a14 = Integers.rotateLeft(a13, 1);
            int a23 = Integers.rotateLeft(a22, 5);
            int a34 = Integers.rotateLeft(a33, 2);
            int a15 = a14 ^ (a34 | a23);
            int a35 = a03 ^ ((a15 ^ -1) & a23);
            int a24 = (((a15 ^ -1) ^ a34) ^ a23) ^ a35;
            int a16 = a15 ^ (a35 | a24);
            a0 = a34 ^ (a24 & a16);
            a1 = Integers.rotateLeft(a16, 31);
            a2 = Integers.rotateLeft(a24, 27);
            a3 = Integers.rotateLeft(a35, 30);
        }
    }

    private int decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        int a0 = Pack.bigEndianToInt(in, inOff);
        int a1 = Pack.bigEndianToInt(in, inOff + 4);
        int a2 = Pack.bigEndianToInt(in, inOff + 8);
        int a3 = Pack.bigEndianToInt(in, inOff + 12);
        int k0 = this.k[0];
        int k1 = this.k[1];
        int k2 = this.k[2];
        int k3 = this.k[3];
        int round = 16;
        while (true) {
            int t02 = a0 ^ a2;
            int t022 = t02 ^ (Integers.rotateLeft(t02, 8) ^ Integers.rotateLeft(t02, 24));
            int a12 = a1 ^ k1;
            int a32 = a3 ^ k3;
            int t13 = a12 ^ a32;
            int t132 = t13 ^ (Integers.rotateLeft(t13, 8) ^ Integers.rotateLeft(t13, 24));
            int a13 = a12 ^ t022;
            int a22 = (a2 ^ k2) ^ t132;
            int a33 = a32 ^ t022;
            int a02 = ((a0 ^ k0) ^ t132) ^ (roundConstants[round] & 255);
            round--;
            if (round < 0) {
                Pack.intToBigEndian(a02, out, outOff);
                Pack.intToBigEndian(a13, out, outOff + 4);
                Pack.intToBigEndian(a22, out, outOff + 8);
                Pack.intToBigEndian(a33, out, outOff + 12);
                return 16;
            }
            int a14 = Integers.rotateLeft(a13, 1);
            int a23 = Integers.rotateLeft(a22, 5);
            int a34 = Integers.rotateLeft(a33, 2);
            int a15 = a14 ^ (a34 | a23);
            int a35 = a02 ^ ((a15 ^ -1) & a23);
            int a24 = (((a15 ^ -1) ^ a34) ^ a23) ^ a35;
            int a16 = a15 ^ (a35 | a24);
            a0 = a34 ^ (a24 & a16);
            a1 = Integers.rotateLeft(a16, 31);
            a2 = Integers.rotateLeft(a24, 27);
            a3 = Integers.rotateLeft(a35, 30);
        }
    }
}
