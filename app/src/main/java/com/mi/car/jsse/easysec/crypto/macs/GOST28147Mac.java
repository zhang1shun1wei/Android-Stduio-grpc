package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithSBox;
import com.mi.car.jsse.easysec.math.ec.Tnaf;

public class GOST28147Mac implements Mac {
    private byte[] S = {9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5, 3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1, 14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9, 14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6, 11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6, 3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6, 1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14, 11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4};
    private int blockSize = 8;
    private byte[] buf = new byte[this.blockSize];
    private int bufOff = 0;
    private boolean firstStep = true;
    private byte[] mac = new byte[this.blockSize];
    private byte[] macIV = null;
    private int macSize = 4;
    private int[] workingKey = null;

    private int[] generateWorkingKey(byte[] userKey) {
        if (userKey.length != 32) {
            throw new IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!");
        }
        int[] key = new int[8];
        for (int i = 0; i != 8; i++) {
            key[i] = bytesToint(userKey, i * 4);
        }
        return key;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void init(CipherParameters params) throws IllegalArgumentException {
        reset();
        this.buf = new byte[this.blockSize];
        this.macIV = null;
        recursiveInit(params);
    }

    private void recursiveInit(CipherParameters params) throws IllegalArgumentException {
        if (params != null) {
            CipherParameters child = null;
            if (params instanceof ParametersWithSBox) {
                ParametersWithSBox param = (ParametersWithSBox) params;
                System.arraycopy(param.getSBox(), 0, this.S, 0, param.getSBox().length);
                child = param.getParameters();
            } else if (params instanceof KeyParameter) {
                this.workingKey = generateWorkingKey(((KeyParameter) params).getKey());
            } else if (params instanceof ParametersWithIV) {
                ParametersWithIV p = (ParametersWithIV) params;
                System.arraycopy(p.getIV(), 0, this.mac, 0, this.mac.length);
                this.macIV = p.getIV();
                child = p.getParameters();
            } else {
                throw new IllegalArgumentException("invalid parameter passed to GOST28147 init - " + params.getClass().getName());
            }
            recursiveInit(child);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public String getAlgorithmName() {
        return "GOST28147Mac";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int getMacSize() {
        return this.macSize;
    }

    private int gost28147_mainStep(int n1, int key) {
        int cm = key + n1;
        int om = (this.S[((cm >> 0) & 15) + 0] << 0) + (this.S[((cm >> 4) & 15) + 16] << 4) + (this.S[((cm >> 8) & 15) + 32] << 8) + (this.S[((cm >> 12) & 15) + 48] << 12) + (this.S[((cm >> 16) & 15) + 64] << Tnaf.POW_2_WIDTH) + (this.S[((cm >> 20) & 15) + 80] << 20) + (this.S[((cm >> 24) & 15) + 96] << 24) + (this.S[((cm >> 28) & 15) + 112] << 28);
        return (om << 11) | (om >>> 21);
    }

    private void gost28147MacFunc(int[] workingKey2, byte[] in, int inOff, byte[] out, int outOff) {
        int N1 = bytesToint(in, inOff);
        int N2 = bytesToint(in, inOff + 4);
        for (int k = 0; k < 2; k++) {
            for (int j = 0; j < 8; j++) {
                N1 = N2 ^ gost28147_mainStep(N1, workingKey2[j]);
                N2 = N1;
            }
        }
        intTobytes(N1, out, outOff);
        intTobytes(N2, out, outOff + 4);
    }

    private int bytesToint(byte[] in, int inOff) {
        return ((in[inOff + 3] << 24) & -16777216) + ((in[inOff + 2] << Tnaf.POW_2_WIDTH) & 16711680) + ((in[inOff + 1] << 8) & 65280) + (in[inOff] & 255);
    }

    private void intTobytes(int num, byte[] out, int outOff) {
        out[outOff + 3] = (byte) (num >>> 24);
        out[outOff + 2] = (byte) (num >>> 16);
        out[outOff + 1] = (byte) (num >>> 8);
        out[outOff] = (byte) num;
    }

    private byte[] CM5func(byte[] buf2, int bufOff2, byte[] mac2) {
        byte[] sum = new byte[(buf2.length - bufOff2)];
        System.arraycopy(buf2, bufOff2, sum, 0, mac2.length);
        for (int i = 0; i != mac2.length; i++) {
            sum[i] = (byte) (sum[i] ^ mac2[i]);
        }
        return sum;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte in) throws IllegalStateException {
        if (this.bufOff == this.buf.length) {
            byte[] sumbuf = new byte[this.buf.length];
            System.arraycopy(this.buf, 0, sumbuf, 0, this.mac.length);
            if (this.firstStep) {
                this.firstStep = false;
                if (this.macIV != null) {
                    sumbuf = CM5func(this.buf, 0, this.macIV);
                }
            } else {
                sumbuf = CM5func(this.buf, 0, this.mac);
            }
            gost28147MacFunc(this.workingKey, sumbuf, 0, this.mac, 0);
            this.bufOff = 0;
        }
        byte[] bArr = this.buf;
        int i = this.bufOff;
        this.bufOff = i + 1;
        bArr[i] = in;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte[] in, int inOff, int len) throws DataLengthException, IllegalStateException {
        if (len < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }
        int gapLen = this.blockSize - this.bufOff;
        if (len > gapLen) {
            System.arraycopy(in, inOff, this.buf, this.bufOff, gapLen);
            byte[] sumbuf = new byte[this.buf.length];
            System.arraycopy(this.buf, 0, sumbuf, 0, this.mac.length);
            if (this.firstStep) {
                this.firstStep = false;
                if (this.macIV != null) {
                    sumbuf = CM5func(this.buf, 0, this.macIV);
                }
            } else {
                sumbuf = CM5func(this.buf, 0, this.mac);
            }
            gost28147MacFunc(this.workingKey, sumbuf, 0, this.mac, 0);
            this.bufOff = 0;
            len -= gapLen;
            inOff += gapLen;
            while (len > this.blockSize) {
                gost28147MacFunc(this.workingKey, CM5func(in, inOff, this.mac), 0, this.mac, 0);
                len -= this.blockSize;
                inOff += this.blockSize;
            }
        }
        System.arraycopy(in, inOff, this.buf, this.bufOff, len);
        this.bufOff += len;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        while (this.bufOff < this.blockSize) {
            this.buf[this.bufOff] = 0;
            this.bufOff++;
        }
        byte[] sumbuf = new byte[this.buf.length];
        System.arraycopy(this.buf, 0, sumbuf, 0, this.mac.length);
        if (this.firstStep) {
            this.firstStep = false;
        } else {
            sumbuf = CM5func(this.buf, 0, this.mac);
        }
        gost28147MacFunc(this.workingKey, sumbuf, 0, this.mac, 0);
        System.arraycopy(this.mac, (this.mac.length / 2) - this.macSize, out, outOff, this.macSize);
        reset();
        return this.macSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void reset() {
        for (int i = 0; i < this.buf.length; i++) {
            this.buf[i] = 0;
        }
        this.bufOff = 0;
        this.firstStep = true;
    }
}
