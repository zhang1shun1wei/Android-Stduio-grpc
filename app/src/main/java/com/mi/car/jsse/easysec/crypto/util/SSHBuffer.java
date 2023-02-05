package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.math.BigInteger;

/* access modifiers changed from: package-private */
public class SSHBuffer {
    private final byte[] buffer;
    private int pos = 0;

    public SSHBuffer(byte[] magic, byte[] buffer2) {
        this.buffer = buffer2;
        for (int i = 0; i != magic.length; i++) {
            if (magic[i] != buffer2[i]) {
                throw new IllegalArgumentException("magic-number incorrect");
            }
        }
        this.pos += magic.length;
    }

    public SSHBuffer(byte[] buffer2) {
        this.buffer = buffer2;
    }

    public int readU32() {
        if (this.pos > this.buffer.length - 4) {
            throw new IllegalArgumentException("4 bytes for U32 exceeds buffer.");
        }
        byte[] bArr = this.buffer;
        int i = this.pos;
        this.pos = i + 1;
        int i2 = (bArr[i] & 255) << 24;
        byte[] bArr2 = this.buffer;
        int i3 = this.pos;
        this.pos = i3 + 1;
        int i4 = i2 | ((bArr2[i3] & 255) << 16);
        byte[] bArr3 = this.buffer;
        int i5 = this.pos;
        this.pos = i5 + 1;
        int i6 = i4 | ((bArr3[i5] & 255) << 8);
        byte[] bArr4 = this.buffer;
        int i7 = this.pos;
        this.pos = i7 + 1;
        return i6 | (bArr4[i7] & 255);
    }

    public String readString() {
        return Strings.fromByteArray(readBlock());
    }

    public byte[] readBlock() {
        int len = readU32();
        if (len == 0) {
            return new byte[0];
        }
        if (this.pos > this.buffer.length - len) {
            throw new IllegalArgumentException("not enough data for block");
        }
        int start = this.pos;
        this.pos += len;
        return Arrays.copyOfRange(this.buffer, start, this.pos);
    }

    public void skipBlock() {
        int len = readU32();
        if (this.pos > this.buffer.length - len) {
            throw new IllegalArgumentException("not enough data for block");
        }
        this.pos += len;
    }

    public byte[] readPaddedBlock() {
        return readPaddedBlock(8);
    }

    public byte[] readPaddedBlock(int blockSize) {
        int lastByte;
        int len = readU32();
        if (len == 0) {
            return new byte[0];
        }
        if (this.pos > this.buffer.length - len) {
            throw new IllegalArgumentException("not enough data for block");
        } else if (len % blockSize != 0) {
            throw new IllegalArgumentException("missing padding");
        } else {
            int start = this.pos;
            this.pos += len;
            int end = this.pos;
            if (len > 0 && (lastByte = this.buffer[this.pos - 1] & 255) > 0 && lastByte < blockSize) {
                end -= lastByte;
                int i = 1;
                int padPos = end;
                while (i <= lastByte) {
                    if (i != (this.buffer[padPos] & 255)) {
                        throw new IllegalArgumentException("incorrect padding");
                    }
                    i++;
                    padPos++;
                }
            }
            return Arrays.copyOfRange(this.buffer, start, end);
        }
    }

    public BigInteger readBigNumPositive() {
        int len = readU32();
        if (this.pos + len > this.buffer.length) {
            throw new IllegalArgumentException("not enough data for big num");
        }
        int start = this.pos;
        this.pos += len;
        return new BigInteger(1, Arrays.copyOfRange(this.buffer, start, this.pos));
    }

    public byte[] getBuffer() {
        return Arrays.clone(this.buffer);
    }

    public boolean hasRemaining() {
        return this.pos < this.buffer.length;
    }
}
