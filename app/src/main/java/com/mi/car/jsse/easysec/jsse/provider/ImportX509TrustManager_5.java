package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509TrustManager;

/* access modifiers changed from: package-private */
public class ImportX509TrustManager_5 extends BCX509ExtendedTrustManager implements ImportX509TrustManager {
    final JcaJceHelper helper;
    final boolean isInFipsMode;
    final X509TrustManager x509TrustManager;

    ImportX509TrustManager_5(boolean isInFipsMode2, JcaJceHelper helper2, X509TrustManager x509TrustManager2) {
        this.isInFipsMode = isInFipsMode2;
        this.helper = helper2;
        this.x509TrustManager = x509TrustManager2;
    }

    @Override // com.mi.car.jsse.easysec.jsse.provider.ImportX509TrustManager
    public X509TrustManager unwrap() {
        return this.x509TrustManager;
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(copyChain(chain), authType);
        checkAdditionalTrust(chain, authType, null, false);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(copyChain(chain), authType);
        checkAdditionalTrust(chain, authType, TransportData.from(socket), false);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(copyChain(chain), authType);
        checkAdditionalTrust(chain, authType, TransportData.from(engine), false);
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(copyChain(chain), authType);
        checkAdditionalTrust(chain, authType, null, true);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(copyChain(chain), authType);
        checkAdditionalTrust(chain, authType, TransportData.from(socket), true);
    }

    @Override // com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(copyChain(chain), authType);
        checkAdditionalTrust(chain, authType, TransportData.from(engine), true);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return this.x509TrustManager.getAcceptedIssuers();
    }

    private void checkAdditionalTrust(X509Certificate[] chain, String authType, TransportData transportData, boolean checkServerTrusted) throws CertificateException {
        checkAlgorithmConstraints(chain, authType, transportData, checkServerTrusted);
        ProvX509TrustManager.checkExtendedTrust(chain, transportData, checkServerTrusted);
    }

    private void checkAlgorithmConstraints(X509Certificate[] chain, String authType, TransportData transportData, boolean checkServerTrusted) throws CertificateException {
        try {
            ProvAlgorithmChecker.checkChain(this.isInFipsMode, this.helper, TransportData.getAlgorithmConstraints(transportData, false), getTrustedCerts(), chain, ProvX509TrustManager.getRequiredExtendedKeyUsage(checkServerTrusted), ProvX509TrustManager.getRequiredKeyUsage(checkServerTrusted, authType));
        } catch (GeneralSecurityException e) {
            throw new CertificateException("Certificates do not conform to algorithm constraints", e);
        }
    }

    private Set<X509Certificate> getTrustedCerts() {
        X509Certificate[] issuers = getAcceptedIssuers();
        if (TlsUtils.isNullOrEmpty(issuers)) {
            return Collections.emptySet();
        }
        Set<X509Certificate> trustedCerts = new HashSet<>();
        for (X509Certificate issuer : issuers) {
            if (issuer != null) {
                trustedCerts.add(issuer);
            }
        }
        return Collections.unmodifiableSet(trustedCerts);
    }

    private static X509Certificate[] checkChain(X509Certificate[] chain) {
        if (!TlsUtils.isNullOrEmpty(chain)) {
            return chain;
        }
        throw new IllegalArgumentException("'chain' must be a chain of at least one certificate");
    }

    private static X509Certificate[] copyChain(X509Certificate[] chain) {
        return (X509Certificate[]) checkChain(chain).clone();
    }
}
