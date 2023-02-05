package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;

public class NISTCTSBlockCipher extends BufferedBlockCipher {
    public static final int CS1 = 1;
    public static final int CS2 = 2;
    public static final int CS3 = 3;
    private final int blockSize;
    private final int type;

    public NISTCTSBlockCipher(int type2, BlockCipher cipher) {
        this.type = type2;
        this.cipher = new CBCBlockCipher(cipher);
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
            if (this.bufOff < blockSize2) {
                throw new DataLengthException("need at least one block of input for NISTCTS");
            } else if (this.bufOff > blockSize2) {
                byte[] lastBlock = new byte[blockSize2];
                if (this.type == 2 || this.type == 3) {
                    this.cipher.processBlock(this.buf, 0, block, 0);
                    System.arraycopy(this.buf, blockSize2, lastBlock, 0, len);
                    this.cipher.processBlock(lastBlock, 0, lastBlock, 0);
                    if (this.type == 2 && len == blockSize2) {
                        System.arraycopy(block, 0, out, outOff, blockSize2);
                        System.arraycopy(lastBlock, 0, out, outOff + blockSize2, len);
                    } else {
                        System.arraycopy(lastBlock, 0, out, outOff, blockSize2);
                        System.arraycopy(block, 0, out, outOff + blockSize2, len);
                    }
                } else {
                    System.arraycopy(this.buf, 0, block, 0, blockSize2);
                    this.cipher.processBlock(block, 0, block, 0);
                    System.arraycopy(block, 0, out, outOff, len);
                    System.arraycopy(this.buf, this.bufOff - len, lastBlock, 0, len);
                    this.cipher.processBlock(lastBlock, 0, lastBlock, 0);
                    System.arraycopy(lastBlock, 0, out, outOff + len, blockSize2);
                }
            } else {
                this.cipher.processBlock(this.buf, 0, block, 0);
                System.arraycopy(block, 0, out, outOff, blockSize2);
            }
        } else if (this.bufOff < blockSize2) {
            throw new DataLengthException("need at least one block of input for CTS");
        } else {
            byte[] lastBlock2 = new byte[blockSize2];
            if (this.bufOff <= blockSize2) {
                this.cipher.processBlock(this.buf, 0, block, 0);
                System.arraycopy(block, 0, out, outOff, blockSize2);
            } else if (this.type == 3 || (this.type == 2 && (this.buf.length - this.bufOff) % blockSize2 != 0)) {
                if (this.cipher instanceof CBCBlockCipher) {
                    ((CBCBlockCipher) this.cipher).getUnderlyingCipher().processBlock(this.buf, 0, block, 0);
                } else {
                    this.cipher.processBlock(this.buf, 0, block, 0);
                }
                for (int i = blockSize2; i != this.bufOff; i++) {
                    lastBlock2[i - blockSize2] = (byte) (block[i - blockSize2] ^ this.buf[i]);
                }
                System.arraycopy(this.buf, blockSize2, block, 0, len);
                this.cipher.processBlock(block, 0, out, outOff);
                System.arraycopy(lastBlock2, 0, out, outOff + blockSize2, len);
            } else {
                ((CBCBlockCipher) this.cipher).getUnderlyingCipher().processBlock(this.buf, this.bufOff - blockSize2, lastBlock2, 0);
                System.arraycopy(this.buf, 0, block, 0, blockSize2);
                if (len != blockSize2) {
                    System.arraycopy(lastBlock2, len, block, len, blockSize2 - len);
                }
                this.cipher.processBlock(block, 0, block, 0);
                System.arraycopy(block, 0, out, outOff, blockSize2);
                for (int i2 = 0; i2 != len; i2++) {
                    lastBlock2[i2] = (byte) (lastBlock2[i2] ^ this.buf[i2]);
                }
                System.arraycopy(lastBlock2, 0, out, outOff + blockSize2, len);
            }
        }
        int offset = this.bufOff;
        reset();
        return offset;
    }
}
