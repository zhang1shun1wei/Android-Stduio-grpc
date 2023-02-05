package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.StreamBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;

public class OFBBlockCipher extends StreamBlockCipher {
    private byte[] IV;
    private final int blockSize;
    private int byteCount;
    private final BlockCipher cipher;
    private byte[] ofbOutV;
    private byte[] ofbV;

    public OFBBlockCipher(BlockCipher cipher2, int bitBlockSize) {
        super(cipher2);
        if (bitBlockSize > cipher2.getBlockSize() * 8 || bitBlockSize < 8 || bitBlockSize % 8 != 0) {
            throw new IllegalArgumentException("0FB" + bitBlockSize + " not supported");
        }
        this.cipher = cipher2;
        this.blockSize = bitBlockSize / 8;
        this.IV = new byte[cipher2.getBlockSize()];
        this.ofbV = new byte[cipher2.getBlockSize()];
        this.ofbOutV = new byte[cipher2.getBlockSize()];
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public void init(boolean encrypting, CipherParameters params) throws IllegalArgumentException {
        if (params instanceof ParametersWithIV) {
            ParametersWithIV ivParam = (ParametersWithIV) params;
            byte[] iv = ivParam.getIV();
            if (iv.length < this.IV.length) {
                System.arraycopy(iv, 0, this.IV, this.IV.length - iv.length, iv.length);
                for (int i = 0; i < this.IV.length - iv.length; i++) {
                    this.IV[i] = 0;
                }
            } else {
                System.arraycopy(iv, 0, this.IV, 0, this.IV.length);
            }
            reset();
            if (ivParam.getParameters() != null) {
                this.cipher.init(true, ivParam.getParameters());
                return;
            }
            return;
        }
        reset();
        if (params != null) {
            this.cipher.init(true, params);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/OFB" + (this.blockSize * 8);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return this.blockSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        processBytes(in, inOff, this.blockSize, out, outOff);
        return this.blockSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public void reset() {
        System.arraycopy(this.IV, 0, this.ofbV, 0, this.IV.length);
        this.byteCount = 0;
        this.cipher.reset();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.StreamBlockCipher
    public byte calculateByte(byte in) throws DataLengthException, IllegalStateException {
        if (this.byteCount == 0) {
            this.cipher.processBlock(this.ofbV, 0, this.ofbOutV, 0);
        }
        byte[] bArr = this.ofbOutV;
        int i = this.byteCount;
        this.byteCount = i + 1;
        byte rv = (byte) (bArr[i] ^ in);
        if (this.byteCount == this.blockSize) {
            this.byteCount = 0;
            System.arraycopy(this.ofbV, this.blockSize, this.ofbV, 0, this.ofbV.length - this.blockSize);
            System.arraycopy(this.ofbOutV, 0, this.ofbV, this.ofbV.length - this.blockSize, this.blockSize);
        }
        return rv;
    }
}
