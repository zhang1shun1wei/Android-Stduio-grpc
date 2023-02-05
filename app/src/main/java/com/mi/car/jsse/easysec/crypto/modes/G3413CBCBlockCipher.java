package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;

public class G3413CBCBlockCipher implements BlockCipher {
    private byte[] R;
    private byte[] R_init;
    private int blockSize;
    private BlockCipher cipher;
    private boolean forEncryption;
    private boolean initialized = false;
    private int m;

    public G3413CBCBlockCipher(BlockCipher cipher2) {
        this.blockSize = cipher2.getBlockSize();
        this.cipher = cipher2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean forEncryption2, CipherParameters params) throws IllegalArgumentException {
        this.forEncryption = forEncryption2;
        if (params instanceof ParametersWithIV) {
            ParametersWithIV ivParam = (ParametersWithIV) params;
            byte[] iv = ivParam.getIV();
            if (iv.length < this.blockSize) {
                throw new IllegalArgumentException("Parameter m must blockSize <= m");
            }
            this.m = iv.length;
            initArrays();
            this.R_init = Arrays.clone(iv);
            System.arraycopy(this.R_init, 0, this.R, 0, this.R_init.length);
            if (ivParam.getParameters() != null) {
                this.cipher.init(forEncryption2, ivParam.getParameters());
            }
        } else {
            setupDefaultParams();
            initArrays();
            System.arraycopy(this.R_init, 0, this.R, 0, this.R_init.length);
            if (params != null) {
                this.cipher.init(forEncryption2, params);
            }
        }
        this.initialized = true;
    }

    private void initArrays() {
        this.R = new byte[this.m];
        this.R_init = new byte[this.m];
    }

    private void setupDefaultParams() {
        this.m = this.blockSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/CBC";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return this.blockSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        return this.forEncryption ? encrypt(in, inOff, out, outOff) : decrypt(in, inOff, out, outOff);
    }

    private int encrypt(byte[] in, int inOff, byte[] out, int outOff) {
        byte[] sum = GOST3413CipherUtil.sum(GOST3413CipherUtil.copyFromInput(in, this.blockSize, inOff), GOST3413CipherUtil.MSB(this.R, this.blockSize));
        byte[] c = new byte[sum.length];
        this.cipher.processBlock(sum, 0, c, 0);
        System.arraycopy(c, 0, out, outOff, c.length);
        if (out.length > sum.length + outOff) {
            generateR(c);
        }
        return c.length;
    }

    private int decrypt(byte[] in, int inOff, byte[] out, int outOff) {
        byte[] msb = GOST3413CipherUtil.MSB(this.R, this.blockSize);
        byte[] input = GOST3413CipherUtil.copyFromInput(in, this.blockSize, inOff);
        byte[] c = new byte[input.length];
        this.cipher.processBlock(input, 0, c, 0);
        byte[] sum = GOST3413CipherUtil.sum(c, msb);
        System.arraycopy(sum, 0, out, outOff, sum.length);
        if (out.length > sum.length + outOff) {
            generateR(input);
        }
        return sum.length;
    }

    private void generateR(byte[] C) {
        byte[] buf = GOST3413CipherUtil.LSB(this.R, this.m - this.blockSize);
        System.arraycopy(buf, 0, this.R, 0, buf.length);
        System.arraycopy(C, 0, this.R, buf.length, this.m - buf.length);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
        if (this.initialized) {
            System.arraycopy(this.R_init, 0, this.R, 0, this.R_init.length);
            this.cipher.reset();
        }
    }
}
