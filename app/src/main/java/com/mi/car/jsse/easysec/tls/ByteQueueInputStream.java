package com.mi.car.jsse.easysec.tls;

import java.io.InputStream;

public class ByteQueueInputStream extends InputStream {
    private ByteQueue buffer = new ByteQueue();

    public void addBytes(byte[] buf) {
        this.buffer.addData(buf, 0, buf.length);
    }

    public void addBytes(byte[] buf, int bufOff, int bufLen) {
        this.buffer.addData(buf, bufOff, bufLen);
    }

    public int peek(byte[] buf) {
        int bytesToRead = Math.min(this.buffer.available(), buf.length);
        this.buffer.read(buf, 0, bytesToRead, 0);
        return bytesToRead;
    }

    @Override // java.io.InputStream
    public int read() {
        if (this.buffer.available() == 0) {
            return -1;
        }
        return this.buffer.removeData(1, 0)[0] & 255;
    }

    @Override // java.io.InputStream
    public int read(byte[] b) {
        return read(b, 0, b.length);
    }

    @Override // java.io.InputStream
    public int read(byte[] b, int off, int len) {
        int bytesToRead = Math.min(this.buffer.available(), len);
        this.buffer.removeData(b, off, bytesToRead, 0);
        return bytesToRead;
    }

    @Override // java.io.InputStream
    public long skip(long n) {
        int bytesToRemove = Math.min((int) n, this.buffer.available());
        this.buffer.removeData(bytesToRemove);
        return (long) bytesToRemove;
    }

    @Override // java.io.InputStream
    public int available() {
        return this.buffer.available();
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable, java.io.InputStream
    public void close() {
    }
}
