package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;

public class CBCBlockCipher implements BlockCipher {
    private byte[] IV;
    private int blockSize;
    private byte[] cbcNextV;
    private byte[] cbcV;
    private BlockCipher cipher = null;
    private boolean encrypting;

    public CBCBlockCipher(BlockCipher cipher2) {
        this.cipher = cipher2;
        this.blockSize = cipher2.getBlockSize();
        this.IV = new byte[this.blockSize];
        this.cbcV = new byte[this.blockSize];
        this.cbcNextV = new byte[this.blockSize];
    }

    public BlockCipher getUnderlyingCipher() {
        return this.cipher;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean encrypting2, CipherParameters params) throws IllegalArgumentException {
        boolean oldEncrypting = this.encrypting;
        this.encrypting = encrypting2;
        if (params instanceof ParametersWithIV) {
            ParametersWithIV ivParam = (ParametersWithIV) params;
            byte[] iv = ivParam.getIV();
            if (iv.length != this.blockSize) {
                throw new IllegalArgumentException("initialisation vector must be the same length as block size");
            }
            System.arraycopy(iv, 0, this.IV, 0, iv.length);
            reset();
            if (ivParam.getParameters() != null) {
                this.cipher.init(encrypting2, ivParam.getParameters());
            } else if (oldEncrypting != encrypting2) {
                throw new IllegalArgumentException("cannot change encrypting state without providing key.");
            }
        } else {
            reset();
            if (params != null) {
                this.cipher.init(encrypting2, params);
            } else if (oldEncrypting != encrypting2) {
                throw new IllegalArgumentException("cannot change encrypting state without providing key.");
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/CBC";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        return this.encrypting ? encryptBlock(in, inOff, out, outOff) : decryptBlock(in, inOff, out, outOff);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
        System.arraycopy(this.IV, 0, this.cbcV, 0, this.IV.length);
        Arrays.fill(this.cbcNextV, (byte) 0);
        this.cipher.reset();
    }

    private int encryptBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.blockSize + inOff > in.length) {
            throw new DataLengthException("input buffer too short");
        }
        for (int i = 0; i < this.blockSize; i++) {
            byte[] bArr = this.cbcV;
            bArr[i] = (byte) (bArr[i] ^ in[inOff + i]);
        }
        int length = this.cipher.processBlock(this.cbcV, 0, out, outOff);
        System.arraycopy(out, outOff, this.cbcV, 0, this.cbcV.length);
        return length;
    }

    private int decryptBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.blockSize + inOff > in.length) {
            throw new DataLengthException("input buffer too short");
        }
        System.arraycopy(in, inOff, this.cbcNextV, 0, this.blockSize);
        int length = this.cipher.processBlock(in, inOff, out, outOff);
        for (int i = 0; i < this.blockSize; i++) {
            int i2 = outOff + i;
            out[i2] = (byte) (out[i2] ^ this.cbcV[i]);
        }
        byte[] tmp = this.cbcV;
        this.cbcV = this.cbcNextV;
        this.cbcNextV = tmp;
        return length;
    }
}
