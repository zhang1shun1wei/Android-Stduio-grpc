package com.mi.car.jsse.easysec.tls.crypto;

public final class TlsDecodeResult {
    public final byte[] buf;
    public final short contentType;
    public final int len;
    public final int off;

    public TlsDecodeResult(byte[] buf2, int off2, int len2, short contentType2) {
        this.buf = buf2;
        this.off = off2;
        this.len = len2;
        this.contentType = contentType2;
    }
}
