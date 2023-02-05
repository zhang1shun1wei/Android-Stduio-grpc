package com.mi.car.jsse.easysec.tls.crypto;

import java.io.IOException;
import java.math.BigInteger;

public interface TlsSRP6Client {
    BigInteger calculateSecret(BigInteger bigInteger) throws IOException;

    BigInteger generateClientCredentials(byte[] bArr, byte[] bArr2, byte[] bArr3);
}
