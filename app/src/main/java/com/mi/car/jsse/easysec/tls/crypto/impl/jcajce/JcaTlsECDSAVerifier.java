package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import java.security.PublicKey;

public class JcaTlsECDSAVerifier extends JcaTlsDSSVerifier {
    public JcaTlsECDSAVerifier(JcaTlsCrypto crypto, PublicKey publicKey) {
        super(crypto, publicKey, (short) 3, "NoneWithECDSA");
    }
}
