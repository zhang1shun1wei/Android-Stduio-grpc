package com.mi.car.jsse.easysec.crypto.io;

import com.mi.car.jsse.easysec.crypto.Signer;
import java.io.IOException;
import java.io.OutputStream;

public class SignerOutputStream extends OutputStream {
    protected Signer signer;

    public SignerOutputStream(Signer Signer) {
        this.signer = Signer;
    }

    @Override // java.io.OutputStream
    public void write(int b) throws IOException {
        this.signer.update((byte) b);
    }

    @Override // java.io.OutputStream
    public void write(byte[] b, int off, int len) throws IOException {
        this.signer.update(b, off, len);
    }

    public Signer getSigner() {
        return this.signer;
    }
}
