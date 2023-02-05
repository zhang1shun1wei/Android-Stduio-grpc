package com.mi.car.jsse.easysec.oer;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

public class BitBuilder {
    private static final byte[] bits = {Byte.MIN_VALUE, 64, 32, 16, 8, 4, 2, 1};
    byte[] buf = new byte[1];
    int pos = 0;

    public BitBuilder writeBit(int bit) {
        if (this.pos / 8 >= this.buf.length) {
            byte[] newBytes = new byte[(this.buf.length + 4)];
            System.arraycopy(this.buf, 0, newBytes, 0, this.pos / 8);
            Arrays.clear(this.buf);
            this.buf = newBytes;
        }
        if (bit == 0) {
            byte[] bArr = this.buf;
            int i = this.pos / 8;
            bArr[i] = (byte) (bArr[i] & (bits[this.pos % 8] ^ -1));
        } else {
            byte[] bArr2 = this.buf;
            int i2 = this.pos / 8;
            bArr2[i2] = (byte) (bArr2[i2] | bits[this.pos % 8]);
        }
        this.pos++;
        return this;
    }

    public BitBuilder writeBits(long value, int start) {
        for (int p = start - 1; p >= 0; p--) {
            writeBit(((1 << p) & value) > 0 ? 1 : 0);
        }
        return this;
    }

    public BitBuilder writeBits(long value, int start, int len) {
        for (int p = start - 1; p >= start - len; p--) {
            writeBit(((1 << p) & value) != 0 ? 1 : 0);
        }
        return this;
    }

    public int write(OutputStream outputStream) throws IOException {
        int l = (this.pos + (this.pos % 8)) / 8;
        outputStream.write(this.buf, 0, l);
        outputStream.flush();
        return l;
    }

    public int writeAndClear(OutputStream outputStream) throws IOException {
        int l = (this.pos + (this.pos % 8)) / 8;
        outputStream.write(this.buf, 0, l);
        outputStream.flush();
        zero();
        return l;
    }

    public void pad() {
        this.pos += this.pos % 8;
    }

    public void write7BitBytes(int value) {
        boolean writing = false;
        for (int t = 4; t >= 0; t--) {
            if (!writing && (-33554432 & value) != 0) {
                writing = true;
            }
            if (writing) {
                writeBit(t).writeBits((long) value, 32, 7);
            }
            value <<= 7;
        }
    }

    public void write7BitBytes(BigInteger value) {
        int size = (value.bitLength() + (value.bitLength() % 8)) / 8;
        BigInteger mask = BigInteger.valueOf(254).shiftLeft(size * 8);
        boolean writing = false;
        for (int t = size; t >= 0; t--) {
            if (!writing && value.and(mask).compareTo(BigInteger.ZERO) != 0) {
                writing = true;
            }
            if (writing) {
                writeBit(t).writeBits((long) value.and(mask).shiftRight((size * 8) - 8).intValue(), 8, 7);
            }
            value = value.shiftLeft(7);
        }
    }

    /* access modifiers changed from: protected */
    public void finalize() throws Throwable {
        zero();
        super.finalize();
    }

    public void zero() {
        Arrays.clear(this.buf);
        this.pos = 0;
    }
}
