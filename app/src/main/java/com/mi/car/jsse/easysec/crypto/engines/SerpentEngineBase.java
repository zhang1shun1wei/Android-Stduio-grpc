package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.StatelessProcessing;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;

public abstract class SerpentEngineBase implements BlockCipher, StatelessProcessing {
    protected static final int BLOCK_SIZE = 16;
    static final int PHI = -1640531527;
    static final int ROUNDS = 32;
    protected boolean encrypting;
    protected int[] wKey;

    /* access modifiers changed from: protected */
    public abstract void decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2);

    /* access modifiers changed from: protected */
    public abstract void encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2);

    /* access modifiers changed from: protected */
    public abstract int[] makeWorkingKey(byte[] bArr);

    SerpentEngineBase() {
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean encrypting2, CipherParameters params) {
        if (params instanceof KeyParameter) {
            this.encrypting = encrypting2;
            this.wKey = makeWorkingKey(((KeyParameter) params).getKey());
            return;
        }
        throw new IllegalArgumentException("invalid parameter passed to " + getAlgorithmName() + " init - " + params.getClass().getName());
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "Serpent";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public final int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        if (this.wKey == null) {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
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
    }

    protected static int rotateLeft(int x, int bits) {
        return (x << bits) | (x >>> (-bits));
    }

    protected static int rotateRight(int x, int bits) {
        return (x >>> bits) | (x << (-bits));
    }

    /* access modifiers changed from: protected */
    public final void sb0(int[] X, int a, int b, int c, int d) {
        int t1 = a ^ d;
        int t3 = c ^ t1;
        int t4 = b ^ t3;
        X[3] = (a & d) ^ t4;
        int t7 = a ^ (b & t1);
        X[2] = (c | t7) ^ t4;
        int t12 = X[3] & (t3 ^ t7);
        X[1] = (t3 ^ -1) ^ t12;
        X[0] = (t7 ^ -1) ^ t12;
    }

    /* access modifiers changed from: protected */
    public final void ib0(int[] X, int a, int b, int c, int d) {
        int t1 = a ^ -1;
        int t2 = a ^ b;
        int t4 = d ^ (t1 | t2);
        int t5 = c ^ t4;
        X[2] = t2 ^ t5;
        int t8 = t1 ^ (d & t2);
        X[1] = (X[2] & t8) ^ t4;
        X[3] = (a & t4) ^ (X[1] | t5);
        X[0] = X[3] ^ (t5 ^ t8);
    }

    /* access modifiers changed from: protected */
    public final void sb1(int[] X, int a, int b, int c, int d) {
        int t2 = b ^ (a ^ -1);
        int t5 = c ^ (a | t2);
        X[2] = d ^ t5;
        int t7 = b ^ (d | t2);
        int t8 = t2 ^ X[2];
        X[3] = (t5 & t7) ^ t8;
        int t11 = t5 ^ t7;
        X[1] = X[3] ^ t11;
        X[0] = (t8 & t11) ^ t5;
    }

    /* access modifiers changed from: protected */
    public final void ib1(int[] X, int a, int b, int c, int d) {
        int t1 = b ^ d;
        int t3 = a ^ (b & t1);
        int t4 = t1 ^ t3;
        X[3] = c ^ t4;
        int t7 = b ^ (t1 & t3);
        X[1] = t3 ^ (X[3] | t7);
        int t10 = X[1] ^ -1;
        int t11 = X[3] ^ t7;
        X[0] = t10 ^ t11;
        X[2] = (t10 | t11) ^ t4;
    }

    /* access modifiers changed from: protected */
    public final void sb2(int[] X, int a, int b, int c, int d) {
        int t1 = a ^ -1;
        int t2 = b ^ d;
        X[0] = t2 ^ (c & t1);
        int t5 = c ^ t1;
        int t7 = b & (c ^ X[0]);
        X[3] = t5 ^ t7;
        X[2] = ((d | t7) & (X[0] | t5)) ^ a;
        X[1] = (X[3] ^ t2) ^ (X[2] ^ (d | t1));
    }

    /* access modifiers changed from: protected */
    public final void ib2(int[] X, int a, int b, int c, int d) {
        int t1 = b ^ d;
        int t3 = a ^ c;
        int t4 = c ^ t1;
        X[0] = t3 ^ (b & t4);
        X[3] = t1 ^ (t3 | (d ^ (a | (t1 ^ -1))));
        int t11 = t4 ^ -1;
        int t12 = X[0] | X[3];
        X[1] = t11 ^ t12;
        X[2] = (d & t11) ^ (t3 ^ t12);
    }

    /* access modifiers changed from: protected */
    public final void sb3(int[] X, int a, int b, int c, int d) {
        int t1 = a ^ b;
        int t3 = a | d;
        int t4 = c ^ d;
        int t6 = (a & c) | (t1 & t3);
        X[2] = t4 ^ t6;
        int t9 = t6 ^ (b ^ t3);
        X[0] = t1 ^ (t4 & t9);
        int t12 = X[2] & X[0];
        X[1] = t9 ^ t12;
        X[3] = (b | d) ^ (t4 ^ t12);
    }

    /* access modifiers changed from: protected */
    public final void ib3(int[] X, int a, int b, int c, int d) {
        int t2 = b ^ c;
        int t4 = a ^ (b & t2);
        int t6 = d | t4;
        X[0] = t2 ^ t6;
        int t9 = d ^ (t2 | t6);
        X[2] = (c ^ t4) ^ t9;
        int t11 = (a | b) ^ t9;
        X[3] = t4 ^ (X[0] & t11);
        X[1] = X[3] ^ (X[0] ^ t11);
    }

    /* access modifiers changed from: protected */
    public final void sb4(int[] X, int a, int b, int c, int d) {
        int t1 = a ^ d;
        int t3 = c ^ (d & t1);
        int t4 = b | t3;
        X[3] = t1 ^ t4;
        int t6 = b ^ -1;
        X[0] = t3 ^ (t1 | t6);
        int t10 = t1 ^ t6;
        X[2] = (a & X[0]) ^ (t4 & t10);
        X[1] = (a ^ t3) ^ (X[2] & t10);
    }

    /* access modifiers changed from: protected */
    public final void ib4(int[] X, int a, int b, int c, int d) {
        int t3 = b ^ (a & (c | d));
        int t5 = c ^ (a & t3);
        X[1] = d ^ t5;
        int t7 = a ^ -1;
        X[3] = t3 ^ (t5 & X[1]);
        int t11 = d ^ (X[1] | t7);
        X[0] = X[3] ^ t11;
        X[2] = (t3 & t11) ^ (X[1] ^ t7);
    }

    /* access modifiers changed from: protected */
    public final void sb5(int[] X, int a, int b, int c, int d) {
        int t1 = a ^ -1;
        int t2 = a ^ b;
        int t3 = a ^ d;
        X[0] = (c ^ t1) ^ (t2 | t3);
        int t7 = d & X[0];
        X[1] = t7 ^ (t2 ^ X[0]);
        int t12 = t3 ^ (t1 | X[0]);
        X[2] = (t2 | t7) ^ t12;
        X[3] = (b ^ t7) ^ (X[1] & t12);
    }

    /* access modifiers changed from: protected */
    public final void ib5(int[] X, int a, int b, int c, int d) {
        int t1 = c ^ -1;
        int t3 = d ^ (b & t1);
        int t4 = a & t3;
        X[3] = t4 ^ (b ^ t1);
        int t7 = b | X[3];
        X[1] = t3 ^ (a & t7);
        int t10 = a | d;
        X[0] = t10 ^ (t1 ^ t7);
        X[2] = (b & t10) ^ ((a ^ c) | t4);
    }

    /* access modifiers changed from: protected */
    public final void sb6(int[] X, int a, int b, int c, int d) {
        int t2 = a ^ d;
        int t3 = b ^ t2;
        int t5 = c ^ ((a ^ -1) | t2);
        X[1] = b ^ t5;
        int t8 = d ^ (t2 | X[1]);
        X[2] = t3 ^ (t5 & t8);
        int t11 = t5 ^ t8;
        X[0] = X[2] ^ t11;
        X[3] = (t5 ^ -1) ^ (t3 & t11);
    }

    /* access modifiers changed from: protected */
    public final void ib6(int[] X, int a, int b, int c, int d) {
        int t1 = a ^ -1;
        int t2 = a ^ b;
        int t3 = c ^ t2;
        int t5 = d ^ (c | t1);
        X[1] = t3 ^ t5;
        int t8 = t2 ^ (t3 & t5);
        X[3] = t5 ^ (b | t8);
        int t11 = b | X[3];
        X[0] = t8 ^ t11;
        X[2] = (d & t1) ^ (t3 ^ t11);
    }

    /* access modifiers changed from: protected */
    public final void sb7(int[] X, int a, int b, int c, int d) {
        int t1 = b ^ c;
        int t3 = d ^ (c & t1);
        int t4 = a ^ t3;
        X[1] = b ^ (t4 & (d | t1));
        X[3] = t1 ^ (a & t4);
        int t11 = t4 ^ (t3 | X[1]);
        X[2] = t3 ^ (X[3] & t11);
        X[0] = (t11 ^ -1) ^ (X[3] & X[2]);
    }

    /* access modifiers changed from: protected */
    public final void ib7(int[] X, int a, int b, int c, int d) {
        int t3 = c | (a & b);
        int t4 = d & (a | b);
        X[3] = t3 ^ t4;
        int t7 = b ^ t4;
        X[1] = a ^ (t7 | (X[3] ^ (d ^ -1)));
        X[0] = (c ^ t7) ^ (X[1] | d);
        X[2] = (X[1] ^ t3) ^ (X[0] ^ (X[3] & a));
    }

    /* access modifiers changed from: protected */
    public final void LT(int[] X) {
        int x0 = rotateLeft(X[0], 13);
        int x2 = rotateLeft(X[2], 3);
        int x1 = (X[1] ^ x0) ^ x2;
        int x3 = (X[3] ^ x2) ^ (x0 << 3);
        X[1] = rotateLeft(x1, 1);
        X[3] = rotateLeft(x3, 7);
        X[0] = rotateLeft((X[1] ^ x0) ^ X[3], 5);
        X[2] = rotateLeft((X[3] ^ x2) ^ (X[1] << 7), 22);
    }

    /* access modifiers changed from: protected */
    public final void inverseLT(int[] X) {
        int x2 = (rotateRight(X[2], 22) ^ X[3]) ^ (X[1] << 7);
        int x0 = (rotateRight(X[0], 5) ^ X[1]) ^ X[3];
        int x3 = rotateRight(X[3], 7);
        int x1 = rotateRight(X[1], 1);
        X[3] = (x3 ^ x2) ^ (x0 << 3);
        X[1] = (x1 ^ x0) ^ x2;
        X[2] = rotateRight(x2, 3);
        X[0] = rotateRight(x0, 13);
    }
}
