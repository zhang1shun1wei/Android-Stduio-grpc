package com.mi.car.jsse.easysec.tls.crypto;

public final class TlsEncodeResult {
    public final byte[] buf;
    public final int len;
    public final int off;
    public final short recordType;

    public TlsEncodeResult(byte[] buf2, int off2, int len2, short recordType2) {
        this.buf = buf2;
        this.off = off2;
        this.len = len2;
        this.recordType = recordType2;
    }
}
