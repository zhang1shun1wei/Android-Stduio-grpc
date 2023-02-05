package com.mi.car.jsse.easysec.tls.crypto;

import java.security.SecureRandom;

public interface TlsCryptoProvider {
    TlsCrypto create(SecureRandom secureRandom);

    TlsCrypto create(SecureRandom secureRandom, SecureRandom secureRandom2);
}
