package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import java.security.PrivateKey;

public class JcaTlsECDSASigner extends JcaTlsDSSSigner {
    public JcaTlsECDSASigner(JcaTlsCrypto crypto, PrivateKey privateKey) {
        super(crypto, privateKey, (short) 3, "NoneWithECDSA");
    }
}
