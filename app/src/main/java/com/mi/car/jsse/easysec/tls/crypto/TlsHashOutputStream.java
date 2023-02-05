package com.mi.car.jsse.easysec.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

public class TlsHashOutputStream extends OutputStream {
    protected TlsHash hash;

    public TlsHashOutputStream(TlsHash hash2) {
        this.hash = hash2;
    }

    @Override // java.io.OutputStream
    public void write(int b) throws IOException {
        this.hash.update(new byte[]{(byte) b}, 0, 1);
    }

    @Override // java.io.OutputStream
    public void write(byte[] buf, int off, int len) throws IOException {
        this.hash.update(buf, off, len);
    }
}
