package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.BCX509Key;
import com.mi.car.jsse.easysec.tls.SecurityParameters;
import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;

/* access modifiers changed from: package-private */
public interface ProvTlsManager {
    void checkClientTrusted(X509Certificate[] x509CertificateArr, String str) throws IOException;

    void checkServerTrusted(X509Certificate[] x509CertificateArr, String str) throws IOException;

    BCX509Key chooseClientKey(String[] strArr, Principal[] principalArr);

    BCX509Key chooseServerKey(String[] strArr, Principal[] principalArr);

    ContextData getContextData();

    boolean getEnableSessionCreation();

    String getPeerHost();

    String getPeerHostSNI();

    int getPeerPort();

    void notifyHandshakeComplete(ProvSSLConnection provSSLConnection);

    void notifyHandshakeSession(ProvSSLSessionContext provSSLSessionContext, SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters, ProvSSLSession provSSLSession);

    String selectApplicationProtocol(List<String> list);
}
