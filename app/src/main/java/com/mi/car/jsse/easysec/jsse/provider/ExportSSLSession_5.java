package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession;
import java.security.Principal;
import java.security.cert.Certificate;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;

class ExportSSLSession_5 implements SSLSession, ExportSSLSession {
    final BCExtendedSSLSession sslSession;

    ExportSSLSession_5(BCExtendedSSLSession sslSession2) {
        this.sslSession = sslSession2;
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ExportSSLSession
    public BCExtendedSSLSession unwrap() {
        return this.sslSession;
    }

    public boolean equals(Object obj) {
        return obj != null && obj.equals(this.sslSession);
    }

    public int getApplicationBufferSize() {
        return this.sslSession.getApplicationBufferSize();
    }

    public String getCipherSuite() {
        return this.sslSession.getCipherSuite();
    }

    public long getCreationTime() {
        return this.sslSession.getCreationTime();
    }

    public byte[] getId() {
        return this.sslSession.getId();
    }

    public long getLastAccessedTime() {
        return this.sslSession.getLastAccessedTime();
    }

    public Certificate[] getLocalCertificates() {
        return this.sslSession.getLocalCertificates();
    }

    public Principal getLocalPrincipal() {
        return this.sslSession.getLocalPrincipal();
    }

    public int getPacketBufferSize() {
        return this.sslSession.getPacketBufferSize();
    }

    @Override // javax.net.ssl.SSLSession
    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        return OldCertUtil.getPeerCertificateChain(this.sslSession);
    }

    @Override // javax.net.ssl.SSLSession
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        return this.sslSession.getPeerCertificates();
    }

    public String getPeerHost() {
        return this.sslSession.getPeerHost();
    }

    public int getPeerPort() {
        return this.sslSession.getPeerPort();
    }

    @Override // javax.net.ssl.SSLSession
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return this.sslSession.getPeerPrincipal();
    }

    public String getProtocol() {
        return this.sslSession.getProtocol();
    }

    public SSLSessionContext getSessionContext() {
        return this.sslSession.getSessionContext();
    }

    public Object getValue(String name) {
        return this.sslSession.getValue(name);
    }

    public String[] getValueNames() {
        return this.sslSession.getValueNames();
    }

    public int hashCode() {
        return this.sslSession.hashCode();
    }

    public void invalidate() {
        this.sslSession.invalidate();
    }

    public boolean isValid() {
        return this.sslSession.isValid();
    }

    public void putValue(String name, Object value) {
        this.sslSession.putValue(name, value);
    }

    public void removeValue(String name) {
        this.sslSession.removeValue(name);
    }

    public String toString() {
        return this.sslSession.toString();
    }
}
