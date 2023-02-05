package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.paddings.BlockCipherPadding;

public class CFBBlockCipherMac implements Mac {
    private byte[] buf;
    private int bufOff;
    private MacCFBBlockCipher cipher;
    private byte[] mac;
    private int macSize;
    private BlockCipherPadding padding;

    public CFBBlockCipherMac(BlockCipher cipher2) {
        this(cipher2, 8, (cipher2.getBlockSize() * 8) / 2, null);
    }

    public CFBBlockCipherMac(BlockCipher cipher2, BlockCipherPadding padding2) {
        this(cipher2, 8, (cipher2.getBlockSize() * 8) / 2, padding2);
    }

    public CFBBlockCipherMac(BlockCipher cipher2, int cfbBitSize, int macSizeInBits) {
        this(cipher2, cfbBitSize, macSizeInBits, null);
    }

    public CFBBlockCipherMac(BlockCipher cipher2, int cfbBitSize, int macSizeInBits, BlockCipherPadding padding2) {
        this.padding = null;
        if (macSizeInBits % 8 != 0) {
            throw new IllegalArgumentException("MAC size must be multiple of 8");
        }
        this.mac = new byte[cipher2.getBlockSize()];
        this.cipher = new MacCFBBlockCipher(cipher2, cfbBitSize);
        this.padding = padding2;
        this.macSize = macSizeInBits / 8;
        this.buf = new byte[this.cipher.getBlockSize()];
        this.bufOff = 0;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void init(CipherParameters params) {
        reset();
        this.cipher.init(params);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int getMacSize() {
        return this.macSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte in) {
        if (this.bufOff == this.buf.length) {
            this.cipher.processBlock(this.buf, 0, this.mac, 0);
            this.bufOff = 0;
        }
        byte[] bArr = this.buf;
        int i = this.bufOff;
        this.bufOff = i + 1;
        bArr[i] = in;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void update(byte[] in, int inOff, int len) {
        if (len < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }
        int blockSize = this.cipher.getBlockSize();
        int gapLen = blockSize - this.bufOff;
        if (len > gapLen) {
            System.arraycopy(in, inOff, this.buf, this.bufOff, gapLen);
            int resultLen = 0 + this.cipher.processBlock(this.buf, 0, this.mac, 0);
            this.bufOff = 0;
            len -= gapLen;
            inOff += gapLen;
            while (len > blockSize) {
                resultLen += this.cipher.processBlock(in, inOff, this.mac, 0);
                len -= blockSize;
                inOff += blockSize;
            }
        }
        System.arraycopy(in, inOff, this.buf, this.bufOff, len);
        this.bufOff += len;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int doFinal(byte[] out, int outOff) {
        int blockSize = this.cipher.getBlockSize();
        if (this.padding == null) {
            while (this.bufOff < blockSize) {
                this.buf[this.bufOff] = 0;
                this.bufOff++;
            }
        } else {
            this.padding.addPadding(this.buf, this.bufOff);
        }
        this.cipher.processBlock(this.buf, 0, this.mac, 0);
        this.cipher.getMacBlock(this.mac);
        System.arraycopy(this.mac, 0, out, outOff, this.macSize);
        reset();
        return this.macSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void reset() {
        for (int i = 0; i < this.buf.length; i++) {
            this.buf[i] = 0;
        }
        this.bufOff = 0;
        this.cipher.reset();
    }
}
