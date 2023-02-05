package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.crypto.prng.SP800SecureRandom;
import com.mi.car.jsse.easysec.crypto.prng.SP800SecureRandomBuilder;
import com.mi.car.jsse.easysec.tls.crypto.TlsNonceGenerator;
import java.security.SecureRandom;

class JcaNonceGenerator implements TlsNonceGenerator {
    private final SP800SecureRandom random;

    JcaNonceGenerator(SecureRandom entropySource, byte[] additionalData) {
        byte[] nonce = new byte[32];
        entropySource.nextBytes(nonce);
        this.random = new SP800SecureRandomBuilder(entropySource, false).setPersonalizationString(additionalData).buildHash(new SHA512Digest(), nonce, false);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsNonceGenerator
    public byte[] generateNonce(int size) {
        byte[] nonce = new byte[size];
        this.random.nextBytes(nonce);
        return nonce;
    }
}
