package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

class ImportX509TrustManager_7 extends BCX509ExtendedTrustManager implements ImportX509TrustManager {
    final X509ExtendedTrustManager x509TrustManager;

    ImportX509TrustManager_7(X509ExtendedTrustManager x509TrustManager2) {
        this.x509TrustManager = x509TrustManager2;
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ImportX509TrustManager
    public X509TrustManager unwrap() {
        return this.x509TrustManager;
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(chain, authType);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(chain, authType, socket);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(chain, authType, engine);
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(chain, authType);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(chain, authType, socket);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(chain, authType, engine);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return this.x509TrustManager.getAcceptedIssuers();
    }
}
