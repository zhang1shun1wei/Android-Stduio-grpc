package com.mi.car.jsse.easysec.tls.crypto;

import java.io.IOException;

public interface TlsEncryptor {
    byte[] encrypt(byte[] bArr, int i, int i2) throws IOException;
}
