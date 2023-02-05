package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.StreamBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.math.ec.Tnaf;

public class GOFBBlockCipher extends StreamBlockCipher {
    static final int C1 = 16843012;
    static final int C2 = 16843009;
    private byte[] IV;
    int N3;
    int N4;
    private final int blockSize;
    private int byteCount;
    private final BlockCipher cipher;
    boolean firstStep = true;
    private byte[] ofbOutV;
    private byte[] ofbV;

    public GOFBBlockCipher(BlockCipher cipher2) {
        super(cipher2);
        this.cipher = cipher2;
        this.blockSize = cipher2.getBlockSize();
        if (this.blockSize != 8) {
            throw new IllegalArgumentException("GCTR only for 64 bit block ciphers");
        }
        this.IV = new byte[cipher2.getBlockSize()];
        this.ofbV = new byte[cipher2.getBlockSize()];
        this.ofbOutV = new byte[cipher2.getBlockSize()];
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public void init(boolean encrypting, CipherParameters params) throws IllegalArgumentException {
        this.firstStep = true;
        this.N3 = 0;
        this.N4 = 0;
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
        return this.cipher.getAlgorithmName() + "/GCTR";
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
        this.firstStep = true;
        this.N3 = 0;
        this.N4 = 0;
        System.arraycopy(this.IV, 0, this.ofbV, 0, this.IV.length);
        this.byteCount = 0;
        this.cipher.reset();
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

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.StreamBlockCipher
    public byte calculateByte(byte b) {
        if (this.byteCount == 0) {
            if (this.firstStep) {
                this.firstStep = false;
                this.cipher.processBlock(this.ofbV, 0, this.ofbOutV, 0);
                this.N3 = bytesToint(this.ofbOutV, 0);
                this.N4 = bytesToint(this.ofbOutV, 4);
            }
            this.N3 += C2;
            this.N4 += C1;
            if (this.N4 < C1 && this.N4 > 0) {
                this.N4++;
            }
            intTobytes(this.N3, this.ofbV, 0);
            intTobytes(this.N4, this.ofbV, 4);
            this.cipher.processBlock(this.ofbV, 0, this.ofbOutV, 0);
        }
        byte[] bArr = this.ofbOutV;
        int i = this.byteCount;
        this.byteCount = i + 1;
        byte rv = (byte) (bArr[i] ^ b);
        if (this.byteCount == this.blockSize) {
            this.byteCount = 0;
            System.arraycopy(this.ofbV, this.blockSize, this.ofbV, 0, this.ofbV.length - this.blockSize);
            System.arraycopy(this.ofbOutV, 0, this.ofbV, this.ofbV.length - this.blockSize, this.blockSize);
        }
        return rv;
    }
}
