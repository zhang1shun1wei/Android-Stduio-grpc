package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;

/* access modifiers changed from: package-private */
public final class DummyX509TrustManager extends BCX509ExtendedTrustManager {
    static final BCX509ExtendedTrustManager INSTANCE = new DummyX509TrustManager();

    private DummyX509TrustManager() {
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    public X509Certificate[] getAcceptedIssuers() {
        return JsseUtils.EMPTY_X509CERTIFICATES;
    }
}
