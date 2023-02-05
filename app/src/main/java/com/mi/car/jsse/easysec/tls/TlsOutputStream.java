package com.mi.car.jsse.easysec.tls;

import java.io.IOException;
import java.io.OutputStream;

/* access modifiers changed from: package-private */
public class TlsOutputStream extends OutputStream {
    private final TlsProtocol handler;

    TlsOutputStream(TlsProtocol handler2) {
        this.handler = handler2;
    }

    @Override // java.io.OutputStream
    public void write(int b) throws IOException {
        write(new byte[]{(byte) b}, 0, 1);
    }

    @Override // java.io.OutputStream
    public void write(byte[] buf, int offset, int len) throws IOException {
        this.handler.writeApplicationData(buf, offset, len);
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        this.handler.close();
    }
}
