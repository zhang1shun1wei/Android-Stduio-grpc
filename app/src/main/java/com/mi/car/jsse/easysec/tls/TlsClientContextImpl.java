package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;

/* access modifiers changed from: package-private */
public class TlsClientContextImpl extends AbstractTlsContext implements TlsClientContext {
    TlsClientContextImpl(TlsCrypto crypto) {
        super(crypto, 1);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public boolean isServer() {
        return false;
    }
}
