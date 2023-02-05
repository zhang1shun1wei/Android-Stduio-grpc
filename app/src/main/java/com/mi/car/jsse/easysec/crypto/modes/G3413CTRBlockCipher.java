package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.StreamBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;

public class G3413CTRBlockCipher extends StreamBlockCipher {
    private byte[] CTR;
    private byte[] IV;
    private final int blockSize;
    private byte[] buf;
    private int byteCount;
    private final BlockCipher cipher;
    private boolean initialized;
    private final int s;

    public G3413CTRBlockCipher(BlockCipher cipher2) {
        this(cipher2, cipher2.getBlockSize() * 8);
    }

    public G3413CTRBlockCipher(BlockCipher cipher2, int bitBlockSize) {
        super(cipher2);
        this.byteCount = 0;
        if (bitBlockSize < 0 || bitBlockSize > cipher2.getBlockSize() * 8) {
            throw new IllegalArgumentException("Parameter bitBlockSize must be in range 0 < bitBlockSize <= " + (cipher2.getBlockSize() * 8));
        }
        this.cipher = cipher2;
        this.blockSize = cipher2.getBlockSize();
        this.s = bitBlockSize / 8;
        this.CTR = new byte[this.blockSize];
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public void init(boolean encrypting, CipherParameters params) throws IllegalArgumentException {
        if (params instanceof ParametersWithIV) {
            ParametersWithIV ivParam = (ParametersWithIV) params;
            initArrays();
            this.IV = Arrays.clone(ivParam.getIV());
            if (this.IV.length != this.blockSize / 2) {
                throw new IllegalArgumentException("Parameter IV length must be == blockSize/2");
            }
            System.arraycopy(this.IV, 0, this.CTR, 0, this.IV.length);
            for (int i = this.IV.length; i < this.blockSize; i++) {
                this.CTR[i] = 0;
            }
            if (ivParam.getParameters() != null) {
                this.cipher.init(true, ivParam.getParameters());
            }
        } else {
            initArrays();
            if (params != null) {
                this.cipher.init(true, params);
            }
        }
        this.initialized = true;
    }

    private void initArrays() {
        this.IV = new byte[(this.blockSize / 2)];
        this.CTR = new byte[this.blockSize];
        this.buf = new byte[this.s];
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/GCTR";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return this.s;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        processBytes(in, inOff, this.s, out, outOff);
        return this.s;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.StreamBlockCipher
    public byte calculateByte(byte in) {
        if (this.byteCount == 0) {
            this.buf = generateBuf();
        }
        byte rv = (byte) (this.buf[this.byteCount] ^ in);
        this.byteCount++;
        if (this.byteCount == this.s) {
            this.byteCount = 0;
            generateCRT();
        }
        return rv;
    }

    private void generateCRT() {
        byte[] bArr = this.CTR;
        int length = this.CTR.length - 1;
        bArr[length] = (byte) (bArr[length] + 1);
    }

    private byte[] generateBuf() {
        byte[] encryptedCTR = new byte[this.CTR.length];
        this.cipher.processBlock(this.CTR, 0, encryptedCTR, 0);
        return GOST3413CipherUtil.MSB(encryptedCTR, this.s);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher, com.mi.car.jsse.easysec.crypto.StreamCipher
    public void reset() {
        if (this.initialized) {
            System.arraycopy(this.IV, 0, this.CTR, 0, this.IV.length);
            for (int i = this.IV.length; i < this.blockSize; i++) {
                this.CTR[i] = 0;
            }
            this.byteCount = 0;
            this.cipher.reset();
        }
    }
}
