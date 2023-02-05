package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import java.security.PrivateKey;

public class JcaTlsEd448Signer extends JcaTlsEdDSASigner {
    public JcaTlsEd448Signer(JcaTlsCrypto crypto, PrivateKey privateKey) {
        super(crypto, privateKey, (short) 8, "Ed448");
    }
}
