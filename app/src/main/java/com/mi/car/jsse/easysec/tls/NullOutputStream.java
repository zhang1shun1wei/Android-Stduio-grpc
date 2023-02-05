package com.mi.car.jsse.easysec.tls;

import java.io.IOException;
import java.io.OutputStream;

class NullOutputStream extends OutputStream {
    static final NullOutputStream INSTANCE = new NullOutputStream();

    private NullOutputStream() {
    }

    @Override // java.io.OutputStream
    public void write(byte[] buf) throws IOException {
    }

    @Override // java.io.OutputStream
    public void write(byte[] buf, int off, int len) throws IOException {
    }

    @Override // java.io.OutputStream
    public void write(int b) throws IOException {
    }
}
