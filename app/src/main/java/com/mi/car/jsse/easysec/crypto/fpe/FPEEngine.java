package com.mi.car.jsse.easysec.crypto.fpe;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.FPEParameters;
import com.mi.car.jsse.easysec.util.Pack;

public abstract class FPEEngine {
    protected final BlockCipher baseCipher;
    protected boolean forEncryption;
    protected FPEParameters fpeParameters;

    /* access modifiers changed from: protected */
    public abstract int decryptBlock(byte[] bArr, int i, int i2, byte[] bArr2, int i3);

    /* access modifiers changed from: protected */
    public abstract int encryptBlock(byte[] bArr, int i, int i2, byte[] bArr2, int i3);

    public abstract String getAlgorithmName();

    public abstract void init(boolean z, CipherParameters cipherParameters);

    protected FPEEngine(BlockCipher baseCipher2) {
        this.baseCipher = baseCipher2;
    }

    public int processBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff) {
        if (this.fpeParameters == null) {
            throw new IllegalStateException("FPE engine not initialized");
        } else if (length < 0) {
            throw new IllegalArgumentException("input length cannot be negative");
        } else if (inBuf == null || outBuf == null) {
            throw new NullPointerException("buffer value is null");
        } else if (inBuf.length < inOff + length) {
            throw new DataLengthException("input buffer too short");
        } else if (outBuf.length < outOff + length) {
            throw new OutputLengthException("output buffer too short");
        } else if (this.forEncryption) {
            return encryptBlock(inBuf, inOff, length, outBuf, outOff);
        } else {
            return decryptBlock(inBuf, inOff, length, outBuf, outOff);
        }
    }

    protected static short[] toShortArray(byte[] buf) {
        if ((buf.length & 1) != 0) {
            throw new IllegalArgumentException("data must be an even number of bytes for a wide radix");
        }
        short[] rv = new short[(buf.length / 2)];
        for (int i = 0; i != rv.length; i++) {
            rv[i] = Pack.bigEndianToShort(buf, i * 2);
        }
        return rv;
    }

    protected static byte[] toByteArray(short[] buf) {
        byte[] rv = new byte[(buf.length * 2)];
        for (int i = 0; i != buf.length; i++) {
            Pack.shortToBigEndian(buf[i], rv, i * 2);
        }
        return rv;
    }
}
