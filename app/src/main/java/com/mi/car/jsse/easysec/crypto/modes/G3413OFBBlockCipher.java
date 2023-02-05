package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.StreamBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;

public class G3413OFBBlockCipher extends StreamBlockCipher {
    private byte[] R;
    private byte[] R_init;
    private byte[] Y;
    private int blockSize;
    private int byteCount;
    private BlockCipher cipher;
    private boolean initialized = false;
    private int m;

    public G3413OFBBlockCipher(BlockCipher cipher2) {
        super(cipher2);
        this.blockSize = cipher2.getBlockSize();
        this.cipher = cipher2;
        this.Y = new byte[this.blockSize];
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
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
                this.cipher.init(true, ivParam.getParameters());
            }
        } else {
            setupDefaultParams();
            initArrays();
            System.arraycopy(this.R_init, 0, this.R, 0, this.R_init.length);
            if (params != null) {
                this.cipher.init(true, params);
            }
        }
        this.initialized = true;
    }

    private void initArrays() {
        this.R = new byte[this.m];
        this.R_init = new byte[this.m];
    }

    private void setupDefaultParams() {
        this.m = this.blockSize * 2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/OFB";
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

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.StreamBlockCipher
    public byte calculateByte(byte in) {
        if (this.byteCount == 0) {
            generateY();
        }
        byte rv = (byte) (this.Y[this.byteCount] ^ in);
        this.byteCount++;
        if (this.byteCount == getBlockSize()) {
            this.byteCount = 0;
            generateR();
        }
        return rv;
    }

    private void generateY() {
        this.cipher.processBlock(GOST3413CipherUtil.MSB(this.R, this.blockSize), 0, this.Y, 0);
    }

    private void generateR() {
        byte[] buf = GOST3413CipherUtil.LSB(this.R, this.m - this.blockSize);
        System.arraycopy(buf, 0, this.R, 0, buf.length);
        System.arraycopy(this.Y, 0, this.R, buf.length, this.m - buf.length);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public void reset() {
        if (this.initialized) {
            System.arraycopy(this.R_init, 0, this.R, 0, this.R_init.length);
            Arrays.clear(this.Y);
            this.byteCount = 0;
            this.cipher.reset();
        }
    }
}
