package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCSNIServerName;
import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SecurityParameters;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

class ProvSSLSessionHandshake extends ProvSSLSessionBase {
    protected final JsseSecurityParameters jsseSecurityParameters;
    protected final SecurityParameters securityParameters;

    ProvSSLSessionHandshake(ProvSSLSessionContext sslSessionContext, String peerHost, int peerPort, SecurityParameters securityParameters2, JsseSecurityParameters jsseSecurityParameters2) {
        super(sslSessionContext, peerHost, peerPort);
        this.securityParameters = securityParameters2;
        this.jsseSecurityParameters = jsseSecurityParameters2;
    }

    /* access modifiers changed from: package-private */
    public String getApplicationProtocol() {
        return JsseUtils.getApplicationProtocol(this.securityParameters);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public int getCipherSuiteTLS() {
        return this.securityParameters.getCipherSuite();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public byte[] getIDArray() {
        return this.securityParameters.getSessionID();
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public JsseSecurityParameters getJsseSecurityParameters() {
        return this.jsseSecurityParameters;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public JsseSessionParameters getJsseSessionParameters() {
        return null;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public Certificate getLocalCertificateTLS() {
        return this.securityParameters.getLocalCertificate();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession
    public String[] getLocalSupportedSignatureAlgorithms() {
        return SignatureSchemeInfo.getJcaSignatureAlgorithms(this.jsseSecurityParameters.localSigSchemesCert);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession
    public String[] getLocalSupportedSignatureAlgorithmsBC() {
        return SignatureSchemeInfo.getJcaSignatureAlgorithmsBC(this.jsseSecurityParameters.localSigSchemesCert);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public Certificate getPeerCertificateTLS() {
        return this.securityParameters.getPeerCertificate();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession
    public String[] getPeerSupportedSignatureAlgorithms() {
        return SignatureSchemeInfo.getJcaSignatureAlgorithms(this.jsseSecurityParameters.peerSigSchemesCert);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession
    public String[] getPeerSupportedSignatureAlgorithmsBC() {
        return SignatureSchemeInfo.getJcaSignatureAlgorithmsBC(this.jsseSecurityParameters.peerSigSchemesCert);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public ProtocolVersion getProtocolTLS() {
        return this.securityParameters.getNegotiatedVersion();
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession
    public List<BCSNIServerName> getRequestedServerNames() {
        return JsseUtils.convertSNIServerNames(this.securityParameters.getClientServerNames());
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession
    public List<byte[]> getStatusResponses() {
        List<byte[]> statusResponses = this.jsseSecurityParameters.statusResponses;
        if (statusResponses == null || statusResponses.isEmpty()) {
            return Collections.emptyList();
        }
        ArrayList arrayList = new ArrayList(statusResponses.size());
        for (byte[] statusResponse : statusResponses) {
            arrayList.add(statusResponse.clone());
        }
        return Collections.unmodifiableList(arrayList);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.jsse.provider.ProvSSLSessionBase
    public void invalidateTLS() {
    }
}
