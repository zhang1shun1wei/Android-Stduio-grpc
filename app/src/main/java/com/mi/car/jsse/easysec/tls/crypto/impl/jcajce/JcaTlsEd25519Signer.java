package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import java.security.PrivateKey;

public class JcaTlsEd25519Signer extends JcaTlsEdDSASigner {
    public JcaTlsEd25519Signer(JcaTlsCrypto crypto, PrivateKey privateKey) {
        super(crypto, privateKey, (short) 7, "Ed25519");
    }
}
