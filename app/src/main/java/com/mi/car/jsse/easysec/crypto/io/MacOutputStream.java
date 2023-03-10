package com.mi.car.jsse.easysec.crypto.io;

import com.mi.car.jsse.easysec.crypto.Mac;
import java.io.IOException;
import java.io.OutputStream;

public class MacOutputStream extends OutputStream {
    protected Mac mac;

    public MacOutputStream(Mac mac2) {
        this.mac = mac2;
    }

    @Override // java.io.OutputStream
    public void write(int b) throws IOException {
        this.mac.update((byte) b);
    }

    @Override // java.io.OutputStream
    public void write(byte[] b, int off, int len) throws IOException {
        this.mac.update(b, off, len);
    }

    public byte[] getMac() {
        byte[] res = new byte[this.mac.getMacSize()];
        this.mac.doFinal(res, 0);
        return res;
    }
}
