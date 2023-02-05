package com.mi.car.jsse.easysec.tls;

import java.io.IOException;
import java.io.OutputStream;

public class ByteQueueOutputStream extends OutputStream {
    private ByteQueue buffer = new ByteQueue();

    public ByteQueue getBuffer() {
        return this.buffer;
    }

    @Override // java.io.OutputStream
    public void write(int b) throws IOException {
        this.buffer.addData(new byte[]{(byte) b}, 0, 1);
    }

    @Override // java.io.OutputStream
    public void write(byte[] b, int off, int len) throws IOException {
        this.buffer.addData(b, off, len);
    }
}
