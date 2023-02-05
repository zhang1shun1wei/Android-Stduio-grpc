package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;

/* access modifiers changed from: package-private */
public class TlsServerContextImpl extends AbstractTlsContext implements TlsServerContext {
    TlsServerContextImpl(TlsCrypto crypto) {
        super(crypto, 0);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsContext
    public boolean isServer() {
        return true;
    }
}
