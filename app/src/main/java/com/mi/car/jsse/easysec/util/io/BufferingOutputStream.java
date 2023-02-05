package com.mi.car.jsse.easysec.util.io;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.OutputStream;

public class BufferingOutputStream extends OutputStream {
    private final byte[] buf;
    private int bufOff;
    private final OutputStream other;

    public BufferingOutputStream(OutputStream other2) {
        this.other = other2;
        this.buf = new byte[4096];
    }

    public BufferingOutputStream(OutputStream other2, int bufferSize) {
        this.other = other2;
        this.buf = new byte[bufferSize];
    }

    @Override // java.io.OutputStream
    public void write(byte[] bytes, int offset, int len) throws IOException {
        if (len < this.buf.length - this.bufOff) {
            System.arraycopy(bytes, offset, this.buf, this.bufOff, len);
            this.bufOff += len;
            return;
        }
        int gap = this.buf.length - this.bufOff;
        System.arraycopy(bytes, offset, this.buf, this.bufOff, gap);
        this.bufOff += gap;
        flush();
        int offset2 = offset + gap;
        int len2 = len - gap;
        while (len2 >= this.buf.length) {
            this.other.write(bytes, offset2, this.buf.length);
            offset2 += this.buf.length;
            len2 -= this.buf.length;
        }
        if (len2 > 0) {
            System.arraycopy(bytes, offset2, this.buf, this.bufOff, len2);
            this.bufOff += len2;
        }
    }

    @Override // java.io.OutputStream
    public void write(int b) throws IOException {
        byte[] bArr = this.buf;
        int i = this.bufOff;
        this.bufOff = i + 1;
        bArr[i] = (byte) b;
        if (this.bufOff == this.buf.length) {
            flush();
        }
    }

    @Override // java.io.OutputStream, java.io.Flushable
    public void flush() throws IOException {
        this.other.write(this.buf, 0, this.bufOff);
        this.bufOff = 0;
        Arrays.fill(this.buf, (byte) 0);
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        flush();
        this.other.close();
    }
}
