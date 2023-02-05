package com.mi.car.jsse.easysec.tls.crypto;

import java.math.BigInteger;

public interface TlsSRP6VerifierGenerator {
    BigInteger generateVerifier(byte[] bArr, byte[] bArr2, byte[] bArr3);
}
