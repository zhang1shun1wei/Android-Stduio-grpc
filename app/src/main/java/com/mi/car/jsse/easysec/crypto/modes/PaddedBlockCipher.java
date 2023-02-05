package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;

public class PaddedBlockCipher extends BufferedBlockCipher {
    public PaddedBlockCipher(BlockCipher cipher) {
        this.cipher = cipher;
        this.buf = new byte[cipher.getBlockSize()];
        this.bufOff = 0;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BufferedBlockCipher
    public int getOutputSize(int len) {
        int total = len + this.bufOff;
        int leftOver = total % this.buf.length;
        if (leftOver != 0) {
            return (total - leftOver) + this.buf.length;
        }
        if (this.forEncryption) {
            return total + this.buf.length;
        }
        return total;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BufferedBlockCipher
    public int getUpdateOutputSize(int len) {
        int total = len + this.bufOff;
        int leftOver = total % this.buf.length;
        if (leftOver == 0) {
            return total - this.buf.length;
        }
        return total - leftOver;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BufferedBlockCipher
    public int processByte(byte in, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        int resultLen = 0;
        if (this.bufOff == this.buf.length) {
            resultLen = this.cipher.processBlock(this.buf, 0, out, outOff);
            this.bufOff = 0;
        }
        byte[] bArr = this.buf;
        int i = this.bufOff;
        this.bufOff = i + 1;
        bArr[i] = in;
        return resultLen;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BufferedBlockCipher
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (len < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }
        int blockSize = getBlockSize();
        int length = getUpdateOutputSize(len);
        if (length <= 0 || outOff + length <= out.length) {
            int resultLen = 0;
            int gapLen = this.buf.length - this.bufOff;
            if (len > gapLen) {
                System.arraycopy(in, inOff, this.buf, this.bufOff, gapLen);
                resultLen = 0 + this.cipher.processBlock(this.buf, 0, out, outOff);
                this.bufOff = 0;
                len -= gapLen;
                inOff += gapLen;
                while (len > this.buf.length) {
                    resultLen += this.cipher.processBlock(in, inOff, out, outOff + resultLen);
                    len -= blockSize;
                    inOff += blockSize;
                }
            }
            System.arraycopy(in, inOff, this.buf, this.bufOff, len);
            this.bufOff += len;
            return resultLen;
        }
        throw new OutputLengthException("output buffer too short");
    }

    @Override // com.mi.car.jsse.easysec.crypto.BufferedBlockCipher
    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        int resultLen;
        int blockSize = this.cipher.getBlockSize();
        int resultLen2 = 0;
        if (this.forEncryption) {
            if (this.bufOff == blockSize) {
                if ((blockSize * 2) + outOff > out.length) {
                    throw new OutputLengthException("output buffer too short");
                }
                resultLen2 = this.cipher.processBlock(this.buf, 0, out, outOff);
                this.bufOff = 0;
            }
            byte code = (byte) (blockSize - this.bufOff);
            while (this.bufOff < blockSize) {
                this.buf[this.bufOff] = code;
                this.bufOff++;
            }
            resultLen = resultLen2 + this.cipher.processBlock(this.buf, 0, out, outOff + resultLen2);
        } else if (this.bufOff == blockSize) {
            int resultLen3 = this.cipher.processBlock(this.buf, 0, this.buf, 0);
            this.bufOff = 0;
            int count = this.buf[blockSize - 1] & 255;
            if (count > blockSize) {
                throw new InvalidCipherTextException("pad block corrupted");
            }
            resultLen = resultLen3 - count;
            System.arraycopy(this.buf, 0, out, outOff, resultLen);
        } else {
            throw new DataLengthException("last block incomplete in decryption");
        }
        reset();
        return resultLen;
    }
}
