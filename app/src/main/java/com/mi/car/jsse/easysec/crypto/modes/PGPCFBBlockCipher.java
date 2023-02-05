package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;

public class PGPCFBBlockCipher implements BlockCipher {
    private byte[] FR = new byte[this.blockSize];
    private byte[] FRE = new byte[this.blockSize];
    private byte[] IV = new byte[this.blockSize];
    private int blockSize;
    private BlockCipher cipher;
    private int count;
    private boolean forEncryption;
    private boolean inlineIv;
    private byte[] tmp = new byte[this.blockSize];

    public PGPCFBBlockCipher(BlockCipher cipher2, boolean inlineIv2) {
        this.cipher = cipher2;
        this.inlineIv = inlineIv2;
        this.blockSize = cipher2.getBlockSize();
    }

    public BlockCipher getUnderlyingCipher() {
        return this.cipher;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        if (this.inlineIv) {
            return this.cipher.getAlgorithmName() + "/PGPCFBwithIV";
        }
        return this.cipher.getAlgorithmName() + "/PGPCFB";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        return this.inlineIv ? this.forEncryption ? encryptBlockWithIV(in, inOff, out, outOff) : decryptBlockWithIV(in, inOff, out, outOff) : this.forEncryption ? encryptBlock(in, inOff, out, outOff) : decryptBlock(in, inOff, out, outOff);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
        this.count = 0;
        for (int i = 0; i != this.FR.length; i++) {
            if (this.inlineIv) {
                this.FR[i] = 0;
            } else {
                this.FR[i] = this.IV[i];
            }
        }
        this.cipher.reset();
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean forEncryption2, CipherParameters params) throws IllegalArgumentException {
        this.forEncryption = forEncryption2;
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
            this.cipher.init(true, ivParam.getParameters());
            return;
        }
        reset();
        this.cipher.init(true, params);
    }

    private byte encryptByte(byte data, int blockOff) {
        return (byte) (this.FRE[blockOff] ^ data);
    }

    private int encryptBlockWithIV(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.blockSize + inOff > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (this.count != 0) {
            if (this.count >= this.blockSize + 2) {
                if (this.blockSize + outOff > out.length) {
                    throw new OutputLengthException("output buffer too short");
                }
                this.cipher.processBlock(this.FR, 0, this.FRE, 0);
                for (int n = 0; n < this.blockSize; n++) {
                    out[outOff + n] = encryptByte(in[inOff + n], n);
                }
                System.arraycopy(out, outOff, this.FR, 0, this.blockSize);
            }
            return this.blockSize;
        } else if ((this.blockSize * 2) + outOff + 2 > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            this.cipher.processBlock(this.FR, 0, this.FRE, 0);
            for (int n2 = 0; n2 < this.blockSize; n2++) {
                out[outOff + n2] = encryptByte(this.IV[n2], n2);
            }
            System.arraycopy(out, outOff, this.FR, 0, this.blockSize);
            this.cipher.processBlock(this.FR, 0, this.FRE, 0);
            out[this.blockSize + outOff] = encryptByte(this.IV[this.blockSize - 2], 0);
            out[this.blockSize + outOff + 1] = encryptByte(this.IV[this.blockSize - 1], 1);
            System.arraycopy(out, outOff + 2, this.FR, 0, this.blockSize);
            this.cipher.processBlock(this.FR, 0, this.FRE, 0);
            for (int n3 = 0; n3 < this.blockSize; n3++) {
                out[this.blockSize + outOff + 2 + n3] = encryptByte(in[inOff + n3], n3);
            }
            System.arraycopy(out, this.blockSize + outOff + 2, this.FR, 0, this.blockSize);
            this.count += (this.blockSize * 2) + 2;
            return (this.blockSize * 2) + 2;
        }
    }

    private int decryptBlockWithIV(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.blockSize + inOff > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (this.blockSize + outOff > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else if (this.count == 0) {
            for (int n = 0; n < this.blockSize; n++) {
                this.FR[n] = in[inOff + n];
            }
            this.cipher.processBlock(this.FR, 0, this.FRE, 0);
            this.count += this.blockSize;
            return 0;
        } else if (this.count == this.blockSize) {
            System.arraycopy(in, inOff, this.tmp, 0, this.blockSize);
            System.arraycopy(this.FR, 2, this.FR, 0, this.blockSize - 2);
            this.FR[this.blockSize - 2] = this.tmp[0];
            this.FR[this.blockSize - 1] = this.tmp[1];
            this.cipher.processBlock(this.FR, 0, this.FRE, 0);
            for (int n2 = 0; n2 < this.blockSize - 2; n2++) {
                out[outOff + n2] = encryptByte(this.tmp[n2 + 2], n2);
            }
            System.arraycopy(this.tmp, 2, this.FR, 0, this.blockSize - 2);
            this.count += 2;
            return this.blockSize - 2;
        } else {
            if (this.count >= this.blockSize + 2) {
                System.arraycopy(in, inOff, this.tmp, 0, this.blockSize);
                out[outOff + 0] = encryptByte(this.tmp[0], this.blockSize - 2);
                out[outOff + 1] = encryptByte(this.tmp[1], this.blockSize - 1);
                System.arraycopy(this.tmp, 0, this.FR, this.blockSize - 2, 2);
                this.cipher.processBlock(this.FR, 0, this.FRE, 0);
                for (int n3 = 0; n3 < this.blockSize - 2; n3++) {
                    out[outOff + n3 + 2] = encryptByte(this.tmp[n3 + 2], n3);
                }
                System.arraycopy(this.tmp, 2, this.FR, 0, this.blockSize - 2);
            }
            return this.blockSize;
        }
    }

    private int encryptBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.blockSize + inOff > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (this.blockSize + outOff > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            this.cipher.processBlock(this.FR, 0, this.FRE, 0);
            for (int n = 0; n < this.blockSize; n++) {
                out[outOff + n] = encryptByte(in[inOff + n], n);
            }
            for (int n2 = 0; n2 < this.blockSize; n2++) {
                this.FR[n2] = out[outOff + n2];
            }
            return this.blockSize;
        }
    }

    private int decryptBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.blockSize + inOff > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (this.blockSize + outOff > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            this.cipher.processBlock(this.FR, 0, this.FRE, 0);
            for (int n = 0; n < this.blockSize; n++) {
                out[outOff + n] = encryptByte(in[inOff + n], n);
            }
            for (int n2 = 0; n2 < this.blockSize; n2++) {
                this.FR[n2] = in[inOff + n2];
            }
            return this.blockSize;
        }
    }
}
