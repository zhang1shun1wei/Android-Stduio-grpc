package com.mi.car.jsse.easysec.tls.crypto.impl;

import java.io.IOException;

public interface TlsAEADCipherImpl {
    int doFinal(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws IOException;

    int getOutputSize(int i);

    void init(byte[] bArr, int i, byte[] bArr2) throws IOException;

    void setKey(byte[] bArr, int i, int i2) throws IOException;
}
