package com.mi.car.jsse.easysec.pqc.crypto.ntru;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.util.Arrays;

public class IndexGenerator {
    private int N;
    private BitString buf;
    private int c;
    private int counter = 0;
    private int hLen;
    private Digest hashAlg;
    private boolean initialized;
    private int minCallsR;
    private int remLen = 0;
    private byte[] seed;
    private int totLen = 0;

    IndexGenerator(byte[] seed2, NTRUEncryptionParameters params) {
        this.seed = seed2;
        this.N = params.N;
        this.c = params.c;
        this.minCallsR = params.minCallsR;
        this.hashAlg = params.hashAlg;
        this.hLen = this.hashAlg.getDigestSize();
        this.initialized = false;
    }

    /* access modifiers changed from: package-private */
    public int nextIndex() {
        int i;
        if (!this.initialized) {
            this.buf = new BitString();
            byte[] hash = new byte[this.hashAlg.getDigestSize()];
            while (this.counter < this.minCallsR) {
                appendHash(this.buf, hash);
                this.counter++;
            }
            this.totLen = this.minCallsR * 8 * this.hLen;
            this.remLen = this.totLen;
            this.initialized = true;
        }
        do {
            this.totLen += this.c;
            BitString M = this.buf.getTrailing(this.remLen);
            if (this.remLen < this.c) {
                int tmpLen = this.c - this.remLen;
                int cThreshold = this.counter + (((this.hLen + tmpLen) - 1) / this.hLen);
                byte[] hash2 = new byte[this.hashAlg.getDigestSize()];
                while (this.counter < cThreshold) {
                    appendHash(M, hash2);
                    this.counter++;
                    if (tmpLen > this.hLen * 8) {
                        tmpLen -= this.hLen * 8;
                    }
                }
                this.remLen = (this.hLen * 8) - tmpLen;
                this.buf = new BitString();
                this.buf.appendBits(hash2);
            } else {
                this.remLen -= this.c;
            }
            i = M.getLeadingAsInt(this.c);
        } while (i >= (1 << this.c) - ((1 << this.c) % this.N));
        return i % this.N;
    }

    private void appendHash(BitString m, byte[] hash) {
        this.hashAlg.update(this.seed, 0, this.seed.length);
        putInt(this.hashAlg, this.counter);
        this.hashAlg.doFinal(hash, 0);
        m.appendBits(hash);
    }

    private void putInt(Digest hashAlg2, int counter2) {
        hashAlg2.update((byte) (counter2 >> 24));
        hashAlg2.update((byte) (counter2 >> 16));
        hashAlg2.update((byte) (counter2 >> 8));
        hashAlg2.update((byte) counter2);
    }

    public static class BitString {
        byte[] bytes = new byte[4];
        int lastByteBits;
        int numBytes;

        /* access modifiers changed from: package-private */
        public void appendBits(byte[] bytes2) {
            for (int i = 0; i != bytes2.length; i++) {
                appendBits(bytes2[i]);
            }
        }

        public void appendBits(byte b) {
            if (this.numBytes == this.bytes.length) {
                this.bytes = IndexGenerator.copyOf(this.bytes, this.bytes.length * 2);
            }
            if (this.numBytes == 0) {
                this.numBytes = 1;
                this.bytes[0] = b;
                this.lastByteBits = 8;
            } else if (this.lastByteBits == 8) {
                byte[] bArr = this.bytes;
                int i = this.numBytes;
                this.numBytes = i + 1;
                bArr[i] = b;
            } else {
                int s = 8 - this.lastByteBits;
                byte[] bArr2 = this.bytes;
                int i2 = this.numBytes - 1;
                bArr2[i2] = (byte) (bArr2[i2] | ((b & 255) << this.lastByteBits));
                byte[] bArr3 = this.bytes;
                int i3 = this.numBytes;
                this.numBytes = i3 + 1;
                bArr3[i3] = (byte) ((b & 255) >> s);
            }
        }

        public BitString getTrailing(int numBits) {
            BitString newStr = new BitString();
            newStr.numBytes = (numBits + 7) / 8;
            newStr.bytes = new byte[newStr.numBytes];
            for (int i = 0; i < newStr.numBytes; i++) {
                newStr.bytes[i] = this.bytes[i];
            }
            newStr.lastByteBits = numBits % 8;
            if (newStr.lastByteBits == 0) {
                newStr.lastByteBits = 8;
            } else {
                int s = 32 - newStr.lastByteBits;
                newStr.bytes[newStr.numBytes - 1] = (byte) ((newStr.bytes[newStr.numBytes - 1] << s) >>> s);
            }
            return newStr;
        }

        public int getLeadingAsInt(int numBits) {
            int startBit = (((this.numBytes - 1) * 8) + this.lastByteBits) - numBits;
            int startByte = startBit / 8;
            int startBitInStartByte = startBit % 8;
            int sum = (this.bytes[startByte] & 255) >>> startBitInStartByte;
            int shift = 8 - startBitInStartByte;
            for (int i = startByte + 1; i < this.numBytes; i++) {
                sum |= (this.bytes[i] & 255) << shift;
                shift += 8;
            }
            return sum;
        }

        public byte[] getBytes() {
            return Arrays.clone(this.bytes);
        }
    }

    /* access modifiers changed from: private */
    public static byte[] copyOf(byte[] src, int len) {
        byte[] tmp = new byte[len];
        if (len >= src.length) {
            len = src.length;
        }
        System.arraycopy(src, 0, tmp, 0, len);
        return tmp;
    }
}
