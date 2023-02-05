package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.StreamBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;

public class G3413CFBBlockCipher extends StreamBlockCipher {
    private byte[] R;
    private byte[] R_init;
    private int blockSize;
    private int byteCount;
    private BlockCipher cipher;
    private boolean forEncryption;
    private byte[] gamma;
    private byte[] inBuf;
    private boolean initialized;
    private int m;
    private final int s;

    public G3413CFBBlockCipher(BlockCipher cipher2) {
        this(cipher2, cipher2.getBlockSize() * 8);
    }

    public G3413CFBBlockCipher(BlockCipher cipher2, int bitBlockSize) {
        super(cipher2);
        this.initialized = false;
        if (bitBlockSize < 0 || bitBlockSize > cipher2.getBlockSize() * 8) {
            throw new IllegalArgumentException("Parameter bitBlockSize must be in range 0 < bitBlockSize <= " + (cipher2.getBlockSize() * 8));
        }
        this.blockSize = cipher2.getBlockSize();
        this.cipher = cipher2;
        this.s = bitBlockSize / 8;
        this.inBuf = new byte[getBlockSize()];
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
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
        return this.cipher.getAlgorithmName() + "/CFB" + (this.blockSize * 8);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return this.s;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        processBytes(in, inOff, getBlockSize(), out, outOff);
        return getBlockSize();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.StreamBlockCipher
    public byte calculateByte(byte in) {
        if (this.byteCount == 0) {
            this.gamma = createGamma();
        }
        byte rv = (byte) (this.gamma[this.byteCount] ^ in);
        byte[] bArr = this.inBuf;
        int i = this.byteCount;
        this.byteCount = i + 1;
        if (this.forEncryption) {
            in = rv;
        }
        bArr[i] = in;
        if (this.byteCount == getBlockSize()) {
            this.byteCount = 0;
            generateR(this.inBuf);
        }
        return rv;
    }

    /* access modifiers changed from: package-private */
    public byte[] createGamma() {
        byte[] msb = GOST3413CipherUtil.MSB(this.R, this.blockSize);
        byte[] encryptedMsb = new byte[msb.length];
        this.cipher.processBlock(msb, 0, encryptedMsb, 0);
        return GOST3413CipherUtil.MSB(encryptedMsb, this.s);
    }

    /* access modifiers changed from: package-private */
    public void generateR(byte[] C) {
        byte[] buf = GOST3413CipherUtil.LSB(this.R, this.m - this.s);
        System.arraycopy(buf, 0, this.R, 0, buf.length);
        System.arraycopy(C, 0, this.R, buf.length, this.m - buf.length);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public void reset() {
        this.byteCount = 0;
        Arrays.clear(this.inBuf);
        Arrays.clear(this.gamma);
        if (this.initialized) {
            System.arraycopy(this.R_init, 0, this.R, 0, this.R_init.length);
            this.cipher.reset();
        }
    }
}
