package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

class ExportX509TrustManager_7 extends X509ExtendedTrustManager implements ExportX509TrustManager {
    final BCX509ExtendedTrustManager x509TrustManager;

    ExportX509TrustManager_7(BCX509ExtendedTrustManager x509TrustManager2) {
        this.x509TrustManager = x509TrustManager2;
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ExportX509TrustManager
    public BCX509ExtendedTrustManager unwrap() {
        return this.x509TrustManager;
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(x509Certificates, authType);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType, Socket socket) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(x509Certificates, authType, socket);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType, SSLEngine engine) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(x509Certificates, authType, engine);
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(x509Certificates, authType);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType, Socket socket) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(x509Certificates, authType, socket);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType, SSLEngine engine) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(x509Certificates, authType, engine);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return this.x509TrustManager.getAcceptedIssuers();
    }
}
