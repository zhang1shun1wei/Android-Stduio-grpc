package com.mi.car.jsse.easysec.crypto.io;

import com.mi.car.jsse.easysec.crypto.Digest;
import java.io.IOException;
import java.io.OutputStream;

public class DigestOutputStream extends OutputStream {
    protected Digest digest;

    public DigestOutputStream(Digest Digest) {
        this.digest = Digest;
    }

    @Override // java.io.OutputStream
    public void write(int b) throws IOException {
        this.digest.update((byte) b);
    }

    @Override // java.io.OutputStream
    public void write(byte[] b, int off, int len) throws IOException {
        this.digest.update(b, off, len);
    }

    public byte[] getDigest() {
        byte[] res = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(res, 0);
        return res;
    }
}
