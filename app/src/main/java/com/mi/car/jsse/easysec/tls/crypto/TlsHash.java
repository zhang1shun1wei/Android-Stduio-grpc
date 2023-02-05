package com.mi.car.jsse.easysec.tls.crypto;

public interface TlsHash {
    byte[] calculateHash();

    TlsHash cloneHash();

    void reset();

    void update(byte[] bArr, int i, int i2);
}
