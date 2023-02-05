package com.mi.car.jsse.easysec.crypto.io;

import com.mi.car.jsse.easysec.crypto.Signer;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class SignerInputStream extends FilterInputStream {
    protected Signer signer;

    public SignerInputStream(InputStream stream, Signer signer2) {
        super(stream);
        this.signer = signer2;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read() throws IOException {
        int b = this.in.read();
        if (b >= 0) {
            this.signer.update((byte) b);
        }
        return b;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(byte[] b, int off, int len) throws IOException {
        int n = this.in.read(b, off, len);
        if (n > 0) {
            this.signer.update(b, off, n);
        }
        return n;
    }

    public Signer getSigner() {
        return this.signer;
    }
}
