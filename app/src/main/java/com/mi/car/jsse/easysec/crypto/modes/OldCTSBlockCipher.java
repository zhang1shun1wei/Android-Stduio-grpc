package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;

public class OldCTSBlockCipher extends BufferedBlockCipher {
    private int blockSize;

    public OldCTSBlockCipher(BlockCipher cipher) {
        if ((cipher instanceof OFBBlockCipher) || (cipher instanceof CFBBlockCipher)) {
            throw new IllegalArgumentException("CTSBlockCipher can only accept ECB, or CBC ciphers");
        }
        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
        this.buf = new byte[(this.blockSize * 2)];
        this.bufOff = 0;
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
    public int getOutputSize(int len) {
        return this.bufOff + len;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BufferedBlockCipher
    public int processByte(byte in, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        int resultLen = 0;
        if (this.bufOff == this.buf.length) {
            resultLen = this.cipher.processBlock(this.buf, 0, out, outOff);
            System.arraycopy(this.buf, this.blockSize, this.buf, 0, this.blockSize);
            this.bufOff = this.blockSize;
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
        int blockSize2 = getBlockSize();
        int length = getUpdateOutputSize(len);
        if (length <= 0 || outOff + length <= out.length) {
            int resultLen = 0;
            int gapLen = this.buf.length - this.bufOff;
            if (len > gapLen) {
                System.arraycopy(in, inOff, this.buf, this.bufOff, gapLen);
                resultLen = 0 + this.cipher.processBlock(this.buf, 0, out, outOff);
                System.arraycopy(this.buf, blockSize2, this.buf, 0, blockSize2);
                this.bufOff = blockSize2;
                len -= gapLen;
                inOff += gapLen;
                while (len > blockSize2) {
                    System.arraycopy(in, inOff, this.buf, this.bufOff, blockSize2);
                    resultLen += this.cipher.processBlock(this.buf, 0, out, outOff + resultLen);
                    System.arraycopy(this.buf, blockSize2, this.buf, 0, blockSize2);
                    len -= blockSize2;
                    inOff += blockSize2;
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
        if (this.bufOff + outOff > out.length) {
            throw new OutputLengthException("output buffer to small in doFinal");
        }
        int blockSize2 = this.cipher.getBlockSize();
        int len = this.bufOff - blockSize2;
        byte[] block = new byte[blockSize2];
        if (this.forEncryption) {
            this.cipher.processBlock(this.buf, 0, block, 0);
            if (this.bufOff < blockSize2) {
                throw new DataLengthException("need at least one block of input for CTS");
            }
            for (int i = this.bufOff; i != this.buf.length; i++) {
                this.buf[i] = block[i - blockSize2];
            }
            for (int i2 = blockSize2; i2 != this.bufOff; i2++) {
                byte[] bArr = this.buf;
                bArr[i2] = (byte) (bArr[i2] ^ block[i2 - blockSize2]);
            }
            if (this.cipher instanceof CBCBlockCipher) {
                ((CBCBlockCipher) this.cipher).getUnderlyingCipher().processBlock(this.buf, blockSize2, out, outOff);
            } else {
                this.cipher.processBlock(this.buf, blockSize2, out, outOff);
            }
            System.arraycopy(block, 0, out, outOff + blockSize2, len);
        } else {
            byte[] lastBlock = new byte[blockSize2];
            if (this.cipher instanceof CBCBlockCipher) {
                ((CBCBlockCipher) this.cipher).getUnderlyingCipher().processBlock(this.buf, 0, block, 0);
            } else {
                this.cipher.processBlock(this.buf, 0, block, 0);
            }
            for (int i3 = blockSize2; i3 != this.bufOff; i3++) {
                lastBlock[i3 - blockSize2] = (byte) (block[i3 - blockSize2] ^ this.buf[i3]);
            }
            System.arraycopy(this.buf, blockSize2, block, 0, len);
            this.cipher.processBlock(block, 0, out, outOff);
            System.arraycopy(lastBlock, 0, out, outOff + blockSize2, len);
        }
        int offset = this.bufOff;
        reset();
        return offset;
    }
}
