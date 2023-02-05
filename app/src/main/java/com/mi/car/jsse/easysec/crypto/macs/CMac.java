package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.modes.CBCBlockCipher;
import com.mi.car.jsse.easysec.crypto.paddings.ISO7816d4Padding;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Pack;

public class CMac implements Mac {
    private byte[] Lu;
    private byte[] Lu2;
    private byte[] ZEROES;
    private byte[] buf;
    private int bufOff;
    private BlockCipher cipher;
    private byte[] mac;
    private int macSize;
    private byte[] poly;

    public CMac(BlockCipher cipher2) {
        this(cipher2, cipher2.getBlockSize() * 8);
    }

    public CMac(BlockCipher cipher2, int macSizeInBits) {
        if (macSizeInBits % 8 != 0) {
            throw new IllegalArgumentException("MAC size must be multiple of 8");
        } else if (macSizeInBits > cipher2.getBlockSize() * 8) {
            throw new IllegalArgumentException("MAC size must be less or equal to " + (cipher2.getBlockSize() * 8));
        } else {
            this.cipher = new CBCBlockCipher(cipher2);
            this.macSize = macSizeInBits / 8;
            this.poly = lookupPoly(cipher2.getBlockSize());
            this.mac = new byte[cipher2.getBlockSize()];
            this.buf = new byte[cipher2.getBlockSize()];
            this.ZEROES = new byte[cipher2.getBlockSize()];
            this.bufOff = 0;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName();
    }

    private static int shiftLeft(byte[] block, byte[] output) {
        int i = block.length;
        int bit = 0;
        while (true) {
            i--;
            if (i < 0) {
                return bit;
            }
            int b = block[i] & 255;
            output[i] = (byte) ((b << 1) | bit);
            bit = (b >>> 7) & 1;
        }
    }

    private byte[] doubleLu(byte[] in) {
        byte[] ret = new byte[in.length];
        int mask = (-shiftLeft(in, ret)) & GF2Field.MASK;
        int length = in.length - 3;
        ret[length] = (byte) (ret[length] ^ (this.poly[1] & mask));
        int length2 = in.length - 2;
        ret[length2] = (byte) (ret[length2] ^ (this.poly[2] & mask));
        int length3 = in.length - 1;
        ret[length3] = (byte) (ret[length3] ^ (this.poly[3] & mask));
        return ret;
    }

    private static byte[] lookupPoly(int blockSizeLength) {
        int xor;
        switch (blockSizeLength * 8) {
            case 64:
                xor = 27;
                break;
            case 128:
                xor = 135;
                break;
            case 160:
                xor = 45;
                break;
            case BERTags.PRIVATE:
                xor = 135;
                break;
            case BERTags.FLAGS:
                xor = 777;
                break;
            case 256:
                xor = 1061;
                break;
            case 320:
                xor = 27;
                break;
            case 384:
                xor = 4109;
                break;
            case 448:
                xor = 2129;
                break;
            case 512:
                xor = 293;
                break;
            case 768:
                xor = 655377;
                break;
            case 1024:
                xor = 524355;
                break;
            case 2048 /*{ENCODED_INT: 2048}*/:
                xor = 548865;
                break;
            default:
                throw new IllegalArgumentException("Unknown block size for CMAC: " + (blockSizeLength * 8));
        }
        return Pack.intToBigEndian(xor);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public void init(CipherParameters params) {
        validate(params);
        this.cipher.init(true, params);
        byte[] L = new byte[this.ZEROES.length];
        this.cipher.processBlock(this.ZEROES, 0, L, 0);
        this.Lu = doubleLu(L);
        this.Lu2 = doubleLu(this.Lu);
        reset();
    }

    /* access modifiers changed from: package-private */
    public void validate(CipherParameters params) {
        if (params != null && !(params instanceof KeyParameter)) {
            throw new IllegalArgumentException("CMac mode only permits key to be set.");
        }
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
            this.cipher.processBlock(this.buf, 0, this.mac, 0);
            this.bufOff = 0;
            len -= gapLen;
            inOff += gapLen;
            while (len > blockSize) {
                this.cipher.processBlock(in, inOff, this.mac, 0);
                len -= blockSize;
                inOff += blockSize;
            }
        }
        System.arraycopy(in, inOff, this.buf, this.bufOff, len);
        this.bufOff += len;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Mac
    public int doFinal(byte[] out, int outOff) {
        byte[] lu;
        if (this.bufOff == this.cipher.getBlockSize()) {
            lu = this.Lu;
        } else {
            new ISO7816d4Padding().addPadding(this.buf, this.bufOff);
            lu = this.Lu2;
        }
        for (int i = 0; i < this.mac.length; i++) {
            byte[] bArr = this.buf;
            bArr[i] = (byte) (bArr[i] ^ lu[i]);
        }
        this.cipher.processBlock(this.buf, 0, this.mac, 0);
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
