package com.mi.car.jsse.easysec.util.test;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class UncloseableOutputStream extends FilterOutputStream {
    public UncloseableOutputStream(OutputStream s) {
        super(s);
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.io.FilterOutputStream, java.lang.AutoCloseable
    public void close() {
        throw new RuntimeException("close() called on UncloseableOutputStream");
    }

    @Override // java.io.OutputStream, java.io.FilterOutputStream
    public void write(byte[] b, int off, int len) throws IOException {
        this.out.write(b, off, len);
    }
}
