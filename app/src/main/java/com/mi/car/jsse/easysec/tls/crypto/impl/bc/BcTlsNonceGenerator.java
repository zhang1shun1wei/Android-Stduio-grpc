package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.prng.RandomGenerator;
import com.mi.car.jsse.easysec.tls.crypto.TlsNonceGenerator;

final class BcTlsNonceGenerator implements TlsNonceGenerator {
    private final RandomGenerator randomGenerator;

    BcTlsNonceGenerator(RandomGenerator randomGenerator2) {
        this.randomGenerator = randomGenerator2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsNonceGenerator
    public byte[] generateNonce(int size) {
        byte[] nonce = new byte[size];
        this.randomGenerator.nextBytes(nonce);
        return nonce;
    }
}
