package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.StreamBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;

public class KCTRBlockCipher extends StreamBlockCipher {
    private int byteCount;
    private BlockCipher engine;
    private boolean initialised;
    private byte[] iv;
    private byte[] ofbOutV;
    private byte[] ofbV;

    public KCTRBlockCipher(BlockCipher engine2) {
        super(engine2);
        this.engine = engine2;
        this.iv = new byte[engine2.getBlockSize()];
        this.ofbV = new byte[engine2.getBlockSize()];
        this.ofbOutV = new byte[engine2.getBlockSize()];
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        this.initialised = true;
        if (params instanceof ParametersWithIV) {
            ParametersWithIV ivParam = (ParametersWithIV) params;
            byte[] iv2 = ivParam.getIV();
            int diff = this.iv.length - iv2.length;
            Arrays.fill(this.iv, (byte) 0);
            System.arraycopy(iv2, 0, this.iv, diff, iv2.length);
            CipherParameters params2 = ivParam.getParameters();
            if (params2 != null) {
                this.engine.init(true, params2);
            }
            reset();
            return;
        }
        throw new IllegalArgumentException("invalid parameter passed");
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        return this.engine.getAlgorithmName() + "/KCTR";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return this.engine.getBlockSize();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.StreamBlockCipher
    public byte calculateByte(byte b) {
        if (this.byteCount == 0) {
            incrementCounterAt(0);
            checkCounter();
            this.engine.processBlock(this.ofbV, 0, this.ofbOutV, 0);
            byte[] bArr = this.ofbOutV;
            int i = this.byteCount;
            this.byteCount = i + 1;
            return (byte) (bArr[i] ^ b);
        }
        byte[] bArr2 = this.ofbOutV;
        int i2 = this.byteCount;
        this.byteCount = i2 + 1;
        byte b2 = (byte) (bArr2[i2] ^ b);
        if (this.byteCount != this.ofbV.length) {
            return b2;
        }
        this.byteCount = 0;
        return b2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (in.length - inOff < getBlockSize()) {
            throw new DataLengthException("input buffer too short");
        } else if (out.length - outOff < getBlockSize()) {
            throw new OutputLengthException("output buffer too short");
        } else {
            processBytes(in, inOff, getBlockSize(), out, outOff);
            return getBlockSize();
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public void reset() {
        if (this.initialised) {
            this.engine.processBlock(this.iv, 0, this.ofbV, 0);
        }
        this.engine.reset();
        this.byteCount = 0;
    }

    private void incrementCounterAt(int pos) {
        int i = pos;
        while (i < this.ofbV.length) {
            byte[] bArr = this.ofbV;
            int i2 = i + 1;
            byte b = (byte) (bArr[i] + 1);
            bArr[i] = b;
            if (b == 0) {
                i = i2;
            } else {
                return;
            }
        }
    }

    private void checkCounter() {
    }
}
