package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;

/* compiled from: CFBBlockCipherMac */
class MacCFBBlockCipher {
    private byte[] IV;
    private int blockSize;
    private byte[] cfbOutV;
    private byte[] cfbV;
    private BlockCipher cipher = null;

    public MacCFBBlockCipher(BlockCipher cipher2, int bitBlockSize) {
        this.cipher = cipher2;
        this.blockSize = bitBlockSize / 8;
        this.IV = new byte[cipher2.getBlockSize()];
        this.cfbV = new byte[cipher2.getBlockSize()];
        this.cfbOutV = new byte[cipher2.getBlockSize()];
    }

    public void init(CipherParameters params) throws IllegalArgumentException {
        if (params instanceof ParametersWithIV) {
            ParametersWithIV ivParam = (ParametersWithIV) params;
            byte[] iv = ivParam.getIV();
            if (iv.length < this.IV.length) {
                System.arraycopy(iv, 0, this.IV, this.IV.length - iv.length, iv.length);
            } else {
                System.arraycopy(iv, 0, this.IV, 0, this.IV.length);
            }
            reset();
            this.cipher.init(true, ivParam.getParameters());
            return;
        }
        reset();
        this.cipher.init(true, params);
    }

    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/CFB" + (this.blockSize * 8);
    }

    public int getBlockSize() {
        return this.blockSize;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.blockSize + inOff > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (this.blockSize + outOff > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            this.cipher.processBlock(this.cfbV, 0, this.cfbOutV, 0);
            for (int i = 0; i < this.blockSize; i++) {
                out[outOff + i] = (byte) (this.cfbOutV[i] ^ in[inOff + i]);
            }
            System.arraycopy(this.cfbV, this.blockSize, this.cfbV, 0, this.cfbV.length - this.blockSize);
            System.arraycopy(out, outOff, this.cfbV, this.cfbV.length - this.blockSize, this.blockSize);
            return this.blockSize;
        }
    }

    public void reset() {
        System.arraycopy(this.IV, 0, this.cfbV, 0, this.IV.length);
        this.cipher.reset();
    }

    /* access modifiers changed from: package-private */
    public void getMacBlock(byte[] mac) {
        this.cipher.processBlock(this.cfbV, 0, mac, 0);
    }
}
