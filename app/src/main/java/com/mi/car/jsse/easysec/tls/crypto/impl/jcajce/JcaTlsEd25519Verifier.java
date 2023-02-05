package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import java.security.PublicKey;

public class JcaTlsEd25519Verifier extends JcaTlsEdDSAVerifier {
    public JcaTlsEd25519Verifier(JcaTlsCrypto crypto, PublicKey publicKey) {
        super(crypto, publicKey, (short) 7, "Ed25519");
    }
}
