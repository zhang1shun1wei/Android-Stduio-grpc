package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCSSLConnection;
import com.mi.car.jsse.easysec.tls.TlsContext;

class ProvSSLConnection implements BCSSLConnection {
    protected final ProvSSLSession session;
    protected final TlsContext tlsContext;

    ProvSSLConnection(TlsContext tlsContext2, ProvSSLSession session2) {
        this.tlsContext = tlsContext2;
        this.session = session2;
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLConnection
    public String getApplicationProtocol() {
        return JsseUtils.getApplicationProtocol(this.tlsContext.getSecurityParametersConnection());
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLConnection
    public byte[] getChannelBinding(String channelBinding) {
        if (channelBinding.equals("tls-server-end-point")) {
            return this.tlsContext.exportChannelBinding(0);
        }
        if (channelBinding.equals("tls-unique")) {
            return this.tlsContext.exportChannelBinding(1);
        }
        throw new UnsupportedOperationException();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCSSLConnection
    public ProvSSLSession getSession() {
        return this.session;
    }
}
