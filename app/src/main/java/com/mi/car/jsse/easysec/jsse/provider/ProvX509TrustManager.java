//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.asn1.x509.KeyPurposeId;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession;
import com.mi.car.jsse.easysec.jsse.BCSNIHostName;
import com.mi.car.jsse.easysec.jsse.BCSSLParameters;
import com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager;
import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509TrustManager;

class ProvX509TrustManager extends BCX509ExtendedTrustManager {
    private static final Logger LOG = Logger.getLogger(ProvX509TrustManager.class.getName());
    private static final boolean provCheckRevocation = PropertyUtils.getBooleanSystemProperty("com.sun.net.ssl.checkRevocation", false);
    private static final boolean provTrustManagerCheckEKU = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.trustManager.checkEKU", true);
    private static final Map<String, Integer> keyUsagesServer = createKeyUsagesServer();
    private final boolean isInFipsMode;
    private final JcaJceHelper helper;
    private final Set<X509Certificate> trustedCerts;
    private final PKIXBuilderParameters pkixParametersTemplate;
    private final X509TrustManager exportX509TrustManager;

    private static void addKeyUsageServer(Map<String, Integer> keyUsages, int keyUsage, int... keyExchangeAlgorithms) {
        int[] var3 = keyExchangeAlgorithms;
        int var4 = keyExchangeAlgorithms.length;

        for(int var5 = 0; var5 < var4; ++var5) {
            int keyExchangeAlgorithm = var3[var5];
            String authType = JsseUtils.getAuthTypeServer(keyExchangeAlgorithm);
            if (null != keyUsages.put(authType, keyUsage)) {
                throw new IllegalStateException("Duplicate keys in server key usages");
            }
        }

    }

    private static Map<String, Integer> createKeyUsagesServer() {
        Map<String, Integer> keyUsages = new HashMap();
        addKeyUsageServer(keyUsages, 0, 3, 5, 17, 19, 0);
        addKeyUsageServer(keyUsages, 2, 1);
        addKeyUsageServer(keyUsages, 4, 7, 9, 16, 18);
        return Collections.unmodifiableMap(keyUsages);
    }

    ProvX509TrustManager(boolean isInFipsMode, JcaJceHelper helper, Set<TrustAnchor> trustAnchors) throws InvalidAlgorithmParameterException {
        this.isInFipsMode = isInFipsMode;
        this.helper = helper;
        this.trustedCerts = getTrustedCerts(trustAnchors);
        if (this.trustedCerts.isEmpty()) {
            this.pkixParametersTemplate = null;
        } else {
            this.pkixParametersTemplate = new PKIXBuilderParameters(trustAnchors, (CertSelector)null);
            this.pkixParametersTemplate.setRevocationEnabled(provCheckRevocation);
        }

        this.exportX509TrustManager = X509TrustManagerUtil.exportX509TrustManager(this);
    }

    ProvX509TrustManager(boolean isInFipsMode, JcaJceHelper helper, PKIXParameters baseParameters) throws InvalidAlgorithmParameterException {
        this.isInFipsMode = isInFipsMode;
        this.helper = helper;
        this.trustedCerts = getTrustedCerts(baseParameters.getTrustAnchors());
        if (this.trustedCerts.isEmpty()) {
            this.pkixParametersTemplate = null;
        } else if (baseParameters instanceof PKIXBuilderParameters) {
            this.pkixParametersTemplate = (PKIXBuilderParameters)baseParameters;
        } else {
            this.pkixParametersTemplate = new PKIXBuilderParameters(baseParameters.getTrustAnchors(), baseParameters.getTargetCertConstraints());
            this.pkixParametersTemplate.setAnyPolicyInhibited(baseParameters.isAnyPolicyInhibited());
            this.pkixParametersTemplate.setCertPathCheckers(baseParameters.getCertPathCheckers());
            this.pkixParametersTemplate.setCertStores(baseParameters.getCertStores());
            this.pkixParametersTemplate.setDate(baseParameters.getDate());
            this.pkixParametersTemplate.setExplicitPolicyRequired(baseParameters.isExplicitPolicyRequired());
            this.pkixParametersTemplate.setInitialPolicies(baseParameters.getInitialPolicies());
            this.pkixParametersTemplate.setPolicyMappingInhibited(baseParameters.isPolicyMappingInhibited());
            this.pkixParametersTemplate.setPolicyQualifiersRejected(baseParameters.getPolicyQualifiersRejected());
            this.pkixParametersTemplate.setRevocationEnabled(baseParameters.isRevocationEnabled());
            this.pkixParametersTemplate.setSigProvider(baseParameters.getSigProvider());
        }

        this.exportX509TrustManager = X509TrustManagerUtil.exportX509TrustManager(this);
    }

    X509TrustManager getExportX509TrustManager() {
        return this.exportX509TrustManager;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.checkTrusted(chain, authType, (TransportData)null, false);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        this.checkTrusted(chain, authType, TransportData.from(socket), false);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        this.checkTrusted(chain, authType, TransportData.from(engine), false);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.checkTrusted(chain, authType, (TransportData)null, true);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        this.checkTrusted(chain, authType, TransportData.from(socket), true);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        this.checkTrusted(chain, authType, TransportData.from(engine), true);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return (X509Certificate[])this.trustedCerts.toArray(new X509Certificate[this.trustedCerts.size()]);
    }

    private X509Certificate[] buildCertPath(X509Certificate[] chain, BCAlgorithmConstraints algorithmConstraints, List<byte[]> statusResponses) throws GeneralSecurityException {
        X509Certificate eeCert = chain[0];
        if (this.trustedCerts.contains(eeCert)) {
            return new X509Certificate[]{eeCert};
        } else {
            CertificateFactory certificateFactory = this.helper.createCertificateFactory("X.509");
            Provider pkixProvider = certificateFactory.getProvider();
            CertStoreParameters certStoreParameters = this.getCertStoreParameters(eeCert, chain);

            CertStore certStore;
            try {
                certStore = CertStore.getInstance("Collection", certStoreParameters, pkixProvider);
            } catch (GeneralSecurityException var13) {
                certStore = CertStore.getInstance("Collection", certStoreParameters);
            }

            CertPathBuilder pkixBuilder;
            try {
                pkixBuilder = CertPathBuilder.getInstance("PKIX", pkixProvider);
            } catch (NoSuchAlgorithmException var12) {
                pkixBuilder = CertPathBuilder.getInstance("PKIX");
            }

            PKIXBuilderParameters pkixParameters = (PKIXBuilderParameters)this.pkixParametersTemplate.clone();
            pkixParameters.addCertPathChecker(new ProvAlgorithmChecker(this.isInFipsMode, this.helper, algorithmConstraints));
            pkixParameters.addCertStore(certStore);
            pkixParameters.setTargetCertConstraints(createTargetCertConstraints(eeCert, pkixParameters.getTargetCertConstraints()));
            if (!statusResponses.isEmpty()) {
                addStatusResponses(pkixBuilder, pkixParameters, chain, statusResponses);
            }

            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)pkixBuilder.build(pkixParameters);
            return getTrustedChain(result.getCertPath(), result.getTrustAnchor());
        }
    }

    private void checkTrusted(X509Certificate[] chain, String authType, TransportData transportData, boolean checkServerTrusted) throws CertificateException {
        if (TlsUtils.isNullOrEmpty(chain)) {
            throw new IllegalArgumentException("'chain' must be a chain of at least one certificate");
        } else if (TlsUtils.isNullOrEmpty(authType)) {
            throw new IllegalArgumentException("'authType' must be a non-null, non-empty string");
        } else if (null == this.pkixParametersTemplate) {
            throw new CertificateException("Unable to build a CertPath: no PKIXBuilderParameters available");
        } else {
            X509Certificate[] trustedChain = this.validateChain(chain, authType, transportData, checkServerTrusted);
            checkExtendedTrust(trustedChain, transportData, checkServerTrusted);
        }
    }

    private CertStoreParameters getCertStoreParameters(X509Certificate eeCert, X509Certificate[] chain) {
        ArrayList<X509Certificate> certs = new ArrayList(chain.length);
        certs.add(eeCert);

        for(int i = 1; i < chain.length; ++i) {
            if (!this.trustedCerts.contains(chain[i])) {
                certs.add(chain[i]);
            }
        }

        return new CollectionCertStoreParameters(Collections.unmodifiableCollection(certs));
    }

    private X509Certificate[] validateChain(X509Certificate[] chain, String authType, TransportData transportData, boolean checkServerTrusted) throws CertificateException {
        try {
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, false);
            List<byte[]> statusResponses = TransportData.getStatusResponses(transportData);
            X509Certificate[] trustedChain = this.buildCertPath(chain, algorithmConstraints, statusResponses);
            KeyPurposeId ekuOID = getRequiredExtendedKeyUsage(checkServerTrusted);
            int kuBit = getRequiredKeyUsage(checkServerTrusted, authType);
            ProvAlgorithmChecker.checkCertPathExtras(this.helper, algorithmConstraints, trustedChain, ekuOID, kuBit);
            return trustedChain;
        } catch (CertificateException var10) {
            throw var10;
        } catch (CertPathBuilderException var11) {
            throw new CertificateException(var11.getMessage(), var11.getCause());
        } catch (GeneralSecurityException var12) {
            throw new CertificateException("Unable to construct a valid chain", var12);
        }
    }

    static void checkEndpointID(String hostname, X509Certificate certificate, String endpointIDAlg) throws CertificateException {
        hostname = JsseUtils.stripSquareBrackets(hostname);
        if (endpointIDAlg.equalsIgnoreCase("HTTPS")) {
            HostnameUtil.checkHostname(hostname, certificate, true);
        } else {
            if (!endpointIDAlg.equalsIgnoreCase("LDAP") && !endpointIDAlg.equalsIgnoreCase("LDAPS")) {
                throw new CertificateException("Unknown endpoint ID algorithm: " + endpointIDAlg);
            }

            HostnameUtil.checkHostname(hostname, certificate, false);
        }

    }

    static void checkExtendedTrust(X509Certificate[] trustedChain, TransportData transportData, boolean checkServerTrusted) throws CertificateException {
        if (null != transportData) {
            BCSSLParameters parameters = transportData.getParameters();
            String endpointIDAlgorithm = parameters.getEndpointIdentificationAlgorithm();
            if (JsseUtils.isNameSpecified(endpointIDAlgorithm)) {
                BCExtendedSSLSession handshakeSession = transportData.getHandshakeSession();
                if (null == handshakeSession) {
                    throw new CertificateException("No handshake session");
                }

                checkEndpointID(trustedChain[0], endpointIDAlgorithm, checkServerTrusted, handshakeSession);
            }
        }

    }

    static KeyPurposeId getRequiredExtendedKeyUsage(boolean forServer) {
        return !provTrustManagerCheckEKU ? null : (forServer ? KeyPurposeId.id_kp_serverAuth : KeyPurposeId.id_kp_clientAuth);
    }

    static int getRequiredKeyUsage(boolean checkServerTrusted, String authType) throws CertificateException {
        if (!checkServerTrusted) {
            return 0;
        } else {
            Integer requiredKeyUsage = (Integer)keyUsagesServer.get(authType);
            if (null == requiredKeyUsage) {
                throw new CertificateException("Unsupported server authType: " + authType);
            } else {
                return requiredKeyUsage;
            }
        }
    }

    private static void addStatusResponses(CertPathBuilder pkixBuilder, PKIXBuilderParameters pkixParameters, X509Certificate[] chain, List<byte[]> statusResponses) {
        Map<X509Certificate, byte[]> statusResponseMap = new HashMap();
        int count = Math.min(chain.length, statusResponses.size());

        for(int i = 0; i < count; ++i) {
            byte[] statusResponse = (byte[])statusResponses.get(i);
            if (null != statusResponse && statusResponse.length > 0) {
                X509Certificate certificate = chain[i];
                if (!statusResponseMap.containsKey(certificate)) {
                    statusResponseMap.put(certificate, statusResponse);
                }
            }
        }

        if (!statusResponseMap.isEmpty()) {
            try {
                PKIXUtil.addStatusResponses(pkixBuilder, pkixParameters, statusResponseMap);
            } catch (RuntimeException var9) {
                LOG.log(Level.FINE, "Failed to add status responses for revocation checking", var9);
            }
        }

    }

    private static void checkEndpointID(X509Certificate certificate, String endpointIDAlg, boolean checkServerTrusted, BCExtendedSSLSession sslSession) throws CertificateException {
        String peerHost = sslSession.getPeerHost();
        if (checkServerTrusted) {
            BCSNIHostName sniHostName = JsseUtils.getSNIHostName(sslSession.getRequestedServerNames());
            if (null != sniHostName) {
                String hostname = sniHostName.getAsciiName();
                if (!hostname.equalsIgnoreCase(peerHost)) {
                    try {
                        checkEndpointID(hostname, certificate, endpointIDAlg);
                        return;
                    } catch (CertificateException var8) {
                        LOG.log(Level.FINE, "Server's endpoint ID did not match the SNI host_name: " + hostname, var8);
                    }
                }
            }
        }

        checkEndpointID(peerHost, certificate, endpointIDAlg);
    }

    private static X509CertSelector createTargetCertConstraints(final X509Certificate eeCert, final CertSelector userConstraints) {
        return new X509CertSelector() {
            {
                this.setCertificate(eeCert);
            }

            public boolean match(Certificate cert) {
                return super.match(cert) && (null == userConstraints || userConstraints.match(cert));
            }
        };
    }

    private static X509Certificate getTrustedCert(TrustAnchor trustAnchor) throws CertificateException {
        X509Certificate trustedCert = trustAnchor.getTrustedCert();
        if (null == trustedCert) {
            throw new CertificateException("No certificate for TrustAnchor");
        } else {
            return trustedCert;
        }
    }

    private static Set<X509Certificate> getTrustedCerts(Set<TrustAnchor> trustAnchors) {
        Set<X509Certificate> result = new HashSet(trustAnchors.size());
        Iterator var2 = trustAnchors.iterator();

        while(var2.hasNext()) {
            TrustAnchor trustAnchor = (TrustAnchor)var2.next();
            if (null != trustAnchor) {
                X509Certificate trustedCert = trustAnchor.getTrustedCert();
                if (null != trustedCert) {
                    result.add(trustedCert);
                }
            }
        }

        return result;
    }

    private static X509Certificate[] getTrustedChain(CertPath certPath, TrustAnchor trustAnchor) throws CertificateException {
        List<? extends Certificate> certificates = certPath.getCertificates();
        X509Certificate[] result = new X509Certificate[certificates.size() + 1];
        certificates.toArray(result);
        result[result.length - 1] = getTrustedCert(trustAnchor);
        return result;
    }
}