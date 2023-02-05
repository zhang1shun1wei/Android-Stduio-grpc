package com.mi.car.jsse.easysec.tls.crypto;

import java.io.IOException;

public interface TlsSecret {
    byte[] calculateHMAC(int i, byte[] bArr, int i2, int i3);

    TlsSecret deriveUsingPRF(int i, String str, byte[] bArr, int i2) throws IOException;

    void destroy();

    byte[] encrypt(TlsEncryptor tlsEncryptor) throws IOException;

    byte[] extract();

    TlsSecret hkdfExpand(int i, byte[] bArr, int i2);

    TlsSecret hkdfExtract(int i, TlsSecret tlsSecret);

    boolean isAlive();
}
