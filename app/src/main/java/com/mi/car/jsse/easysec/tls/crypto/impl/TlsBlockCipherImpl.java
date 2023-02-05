package com.mi.car.jsse.easysec.tls.crypto.impl;

import java.io.IOException;

import javax.crypto.ShortBufferException;

public interface TlsBlockCipherImpl {
    int doFinal(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws Exception;

    int getBlockSize();

    void init(byte[] bArr, int i, int i2) throws IOException;

    void setKey(byte[] bArr, int i, int i2) throws IOException;
}
