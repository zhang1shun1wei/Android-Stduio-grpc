package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCSNIServerName;
import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SessionParameters;
import com.mi.car.jsse.easysec.tls.TlsSession;
import java.util.List;

/* access modifiers changed from: package-private */
public class ProvSSLSession extends ProvSSLSessionBase {
    static final ProvSSLSession NULL_SESSION = new ProvSSLSession(null, null, -1, null, new JsseSessionParameters(null, null));
    protected final JsseSessionParameters jsseSessionParameters;
    protected final SessionParameters sessionParameters;
    protected final TlsSession tlsSession;

    ProvSSLSession(ProvSSLSessionContext sslSessionContext, String peerHost, int peerPort, TlsSession tlsSession2, JsseSessionParameters jsseSessionParameters2) {
        super(sslSessionContext, peerHost, peerPort);
        this.tlsSession = tlsSession2;
        this.sessionParameters = tlsSession2 == null ? null : tlsSession2.exportSessionParameters();
        this.jsseSessionParameters = jsseSessionParameters2;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public int getCipherSuiteTLS() {
        if (this.sessionParameters == null) {
            return 0;
        }
        return this.sessionParameters.getCipherSuite();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public byte[] getIDArray() {
        if (this.tlsSession == null) {
            return null;
        }
        return this.tlsSession.getSessionID();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public JsseSecurityParameters getJsseSecurityParameters() {
        return null;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public JsseSessionParameters getJsseSessionParameters() {
        return this.jsseSessionParameters;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public Certificate getLocalCertificateTLS() {
        if (this.sessionParameters == null) {
            return null;
        }
        return this.sessionParameters.getLocalCertificate();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession
    public String[] getLocalSupportedSignatureAlgorithms() {
        return null;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public Certificate getPeerCertificateTLS() {
        if (this.sessionParameters == null) {
            return null;
        }
        return this.sessionParameters.getPeerCertificate();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession
    public String[] getPeerSupportedSignatureAlgorithms() {
        return null;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public ProtocolVersion getProtocolTLS() {
        if (this.sessionParameters == null) {
            return null;
        }
        return this.sessionParameters.getNegotiatedVersion();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession
    public List<BCSNIServerName> getRequestedServerNames() {
        throw new UnsupportedOperationException();
    }

    /* access modifiers changed from: package-private */
    public TlsSession getTlsSession() {
        return this.tlsSession;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public void invalidateTLS() {
        if (this.tlsSession != null) {
            this.tlsSession.invalidate();
        }
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public boolean isValid() {
        return super.isValid() && this.tlsSession != null && this.tlsSession.isResumable();
    }
}
