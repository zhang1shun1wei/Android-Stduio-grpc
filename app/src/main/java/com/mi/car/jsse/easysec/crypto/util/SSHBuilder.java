package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/* access modifiers changed from: package-private */
public class SSHBuilder {
    private final ByteArrayOutputStream bos = new ByteArrayOutputStream();

    SSHBuilder() {
    }

    public void u32(int value) {
        this.bos.write((value >>> 24) & GF2Field.MASK);
        this.bos.write((value >>> 16) & GF2Field.MASK);
        this.bos.write((value >>> 8) & GF2Field.MASK);
        this.bos.write(value & GF2Field.MASK);
    }

    public void writeBigNum(BigInteger n) {
        writeBlock(n.toByteArray());
    }

    public void writeBlock(byte[] value) {
        u32(value.length);
        try {
            this.bos.write(value);
        } catch (IOException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    public void writeBytes(byte[] value) {
        try {
            this.bos.write(value);
        } catch (IOException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    public void writeString(String str) {
        writeBlock(Strings.toByteArray(str));
    }

    public byte[] getBytes() {
        return this.bos.toByteArray();
    }

    public byte[] getPaddedBytes() {
        return getPaddedBytes(8);
    }

    public byte[] getPaddedBytes(int blockSize) {
        int align = this.bos.size() % blockSize;
        if (align != 0) {
            int padCount = blockSize - align;
            for (int i = 1; i <= padCount; i++) {
                this.bos.write(i);
            }
        }
        return this.bos.toByteArray();
    }
}
