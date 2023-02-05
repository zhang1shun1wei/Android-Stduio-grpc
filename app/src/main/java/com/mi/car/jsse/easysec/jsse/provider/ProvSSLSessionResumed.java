package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SecurityParameters;
import com.mi.car.jsse.easysec.tls.SessionParameters;
import com.mi.car.jsse.easysec.tls.TlsSession;

class ProvSSLSessionResumed extends ProvSSLSessionHandshake {
    protected final JsseSessionParameters jsseSessionParameters;
    protected final SessionParameters sessionParameters;
    protected final TlsSession tlsSession;

    ProvSSLSessionResumed(ProvSSLSessionContext sslSessionContext, String peerHost, int peerPort, SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters, TlsSession tlsSession2, JsseSessionParameters jsseSessionParameters2) {
        super(sslSessionContext, peerHost, peerPort, securityParameters, jsseSecurityParameters);
        this.tlsSession = tlsSession2;
        this.sessionParameters = tlsSession2.exportSessionParameters();
        this.jsseSessionParameters = jsseSessionParameters2;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase, com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionHandshake
    public int getCipherSuiteTLS() {
        return this.sessionParameters.getCipherSuite();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase, com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionHandshake
    public byte[] getIDArray() {
        return this.tlsSession.getSessionID();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase, com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionHandshake
    public JsseSessionParameters getJsseSessionParameters() {
        return this.jsseSessionParameters;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase, com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionHandshake
    public Certificate getLocalCertificateTLS() {
        return this.sessionParameters.getLocalCertificate();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase, com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionHandshake
    public Certificate getPeerCertificateTLS() {
        return this.sessionParameters.getPeerCertificate();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase, com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionHandshake
    public ProtocolVersion getProtocolTLS() {
        return this.sessionParameters.getNegotiatedVersion();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase, com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionHandshake
    public void invalidateTLS() {
        this.tlsSession.invalidate();
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public boolean isValid() {
        return super.isValid() && this.tlsSession.isResumable();
    }
}
