package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.digests.DSTU7564Digest;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.util.Pack;

public class DSTU7564Mac implements Mac {
    private static final int BITS_IN_BYTE = 8;
    private DSTU7564Digest engine;
    private long inputLength;
    private byte[] invertedKey = null;
    private int macSize;
    private byte[] paddedKey = null;

    public DSTU7564Mac(int macBitSize) {
        this.engine = new DSTU7564Digest(macBitSize);
        this.macSize = macBitSize / 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void init(CipherParameters params) throws IllegalArgumentException {
        this.paddedKey = null;
        reset();
        if (params instanceof KeyParameter) {
            byte[] key = ((KeyParameter) params).getKey();
            this.invertedKey = new byte[key.length];
            this.paddedKey = padKey(key);
            for (int byteIndex = 0; byteIndex < this.invertedKey.length; byteIndex++) {
                this.invertedKey[byteIndex] = (byte) (key[byteIndex] ^ -1);
            }
            this.engine.update(this.paddedKey, 0, this.paddedKey.length);
            return;
        }
        throw new IllegalArgumentException("Bad parameter passed");
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public String getAlgorithmName() {
        return "DSTU7564Mac";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int getMacSize() {
        return this.macSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte in) throws IllegalStateException {
        this.engine.update(in);
        this.inputLength++;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte[] in, int inOff, int len) throws DataLengthException, IllegalStateException {
        if (in.length - inOff < len) {
            throw new DataLengthException("Input buffer too short");
        } else if (this.paddedKey == null) {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        } else {
            this.engine.update(in, inOff, len);
            this.inputLength += (long) len;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.paddedKey == null) {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        } else if (out.length - outOff < this.macSize) {
            throw new OutputLengthException("Output buffer too short");
        } else {
            pad();
            this.engine.update(this.invertedKey, 0, this.invertedKey.length);
            this.inputLength = 0;
            int res = this.engine.doFinal(out, outOff);
            reset();
            return res;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void reset() {
        this.inputLength = 0;
        this.engine.reset();
        if (this.paddedKey != null) {
            this.engine.update(this.paddedKey, 0, this.paddedKey.length);
        }
    }

    private void pad() {
        int extra = this.engine.getByteLength() - ((int) (this.inputLength % ((long) this.engine.getByteLength())));
        if (extra < 13) {
            extra += this.engine.getByteLength();
        }
        byte[] padded = new byte[extra];
        padded[0] = Byte.MIN_VALUE;
        Pack.longToLittleEndian(this.inputLength * 8, padded, padded.length - 12);
        this.engine.update(padded, 0, padded.length);
    }

    private byte[] padKey(byte[] in) {
        int paddedLen = (((in.length + this.engine.getByteLength()) - 1) / this.engine.getByteLength()) * this.engine.getByteLength();
        if (paddedLen - in.length < 13) {
            paddedLen += this.engine.getByteLength();
        }
        byte[] padded = new byte[paddedLen];
        System.arraycopy(in, 0, padded, 0, in.length);
        padded[in.length] = Byte.MIN_VALUE;
        Pack.intToLittleEndian(in.length * 8, padded, padded.length - 12);
        return padded;
    }
}
