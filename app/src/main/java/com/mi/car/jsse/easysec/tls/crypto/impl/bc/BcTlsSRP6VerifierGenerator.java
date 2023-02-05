package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.agreement.srp.SRP6VerifierGenerator;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRP6VerifierGenerator;
import java.math.BigInteger;

final class BcTlsSRP6VerifierGenerator implements TlsSRP6VerifierGenerator {
    private final SRP6VerifierGenerator srp6VerifierGenerator;

    BcTlsSRP6VerifierGenerator(SRP6VerifierGenerator srp6VerifierGenerator2) {
        this.srp6VerifierGenerator = srp6VerifierGenerator2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSRP6VerifierGenerator
    public BigInteger generateVerifier(byte[] salt, byte[] identity, byte[] password) {
        return this.srp6VerifierGenerator.generateVerifier(salt, identity, password);
    }
}
