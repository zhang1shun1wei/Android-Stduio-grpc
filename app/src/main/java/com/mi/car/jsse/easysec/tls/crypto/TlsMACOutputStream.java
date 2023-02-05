package com.mi.car.jsse.easysec.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

public class TlsMACOutputStream extends OutputStream {
    protected TlsMAC mac;

    public TlsMACOutputStream(TlsMAC mac2) {
        this.mac = mac2;
    }

    @Override // java.io.OutputStream
    public void write(int b) throws IOException {
        this.mac.update(new byte[]{(byte) b}, 0, 1);
    }

    @Override // java.io.OutputStream
    public void write(byte[] buf, int off, int len) throws IOException {
        this.mac.update(buf, off, len);
    }
}
