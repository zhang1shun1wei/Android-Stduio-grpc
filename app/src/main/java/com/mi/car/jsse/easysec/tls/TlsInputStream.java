package com.mi.car.jsse.easysec.tls;

import java.io.IOException;
import java.io.InputStream;

/* access modifiers changed from: package-private */
public class TlsInputStream extends InputStream {
    private final TlsProtocol handler;

    TlsInputStream(TlsProtocol handler2) {
        this.handler = handler2;
    }

    @Override // java.io.InputStream
    public int read() throws IOException {
        byte[] buf = new byte[1];
        if (read(buf, 0, 1) <= 0) {
            return -1;
        }
        return buf[0] & 255;
    }

    @Override // java.io.InputStream
    public int read(byte[] buf, int offset, int len) throws IOException {
        return this.handler.readApplicationData(buf, offset, len);
    }

    @Override // java.io.InputStream
    public int available() throws IOException {
        return this.handler.applicationDataAvailable();
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable, java.io.InputStream
    public void close() throws IOException {
        this.handler.close();
    }
}
