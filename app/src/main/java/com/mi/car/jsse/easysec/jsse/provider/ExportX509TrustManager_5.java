package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

class ExportX509TrustManager_5 implements X509TrustManager, ExportX509TrustManager {
    final BCX509ExtendedTrustManager x509TrustManager;

    ExportX509TrustManager_5(BCX509ExtendedTrustManager x509TrustManager2) {
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

    @Override // javax.net.ssl.X509TrustManager
    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(x509Certificates, authType);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return this.x509TrustManager.getAcceptedIssuers();
    }
}
