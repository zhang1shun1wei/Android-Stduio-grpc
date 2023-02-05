package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import java.security.PublicKey;

public class JcaTlsEd448Verifier extends JcaTlsEdDSAVerifier {
    public JcaTlsEd448Verifier(JcaTlsCrypto crypto, PublicKey publicKey) {
        super(crypto, publicKey, (short) 8, "Ed448");
    }
}
