package com.mi.car.jsse.easysec.tls.crypto.impl;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;

public abstract class AbstractTlsCrypto implements TlsCrypto {
    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsSecret adoptSecret(TlsSecret secret) {
        if (secret instanceof AbstractTlsSecret) {
            return createSecret(((AbstractTlsSecret) secret).copyData());
        }
        throw new IllegalArgumentException("unrecognized TlsSecret - cannot copy data: " + secret.getClass().getName());
    }
}
