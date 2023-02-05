package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ocsp.OCSPResponse;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.jsse.BCSNIHostName;
import com.mi.car.jsse.easysec.jsse.BCSNIMatcher;
import com.mi.car.jsse.easysec.jsse.BCSNIServerName;
import com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager;
import com.mi.car.jsse.easysec.jsse.BCX509Key;
import com.mi.car.jsse.easysec.jsse.java.security.BCCryptoPrimitive;
import com.mi.car.jsse.easysec.tls.AlertDescription;
import com.mi.car.jsse.easysec.tls.AlertLevel;
import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.CertificateEntry;
import com.mi.car.jsse.easysec.tls.CertificateStatus;
import com.mi.car.jsse.easysec.tls.NamedGroup;
import com.mi.car.jsse.easysec.tls.ProtocolName;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SecurityParameters;
import com.mi.car.jsse.easysec.tls.ServerName;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.TlsContext;
import com.mi.car.jsse.easysec.tls.TlsCredentialedDecryptor;
import com.mi.car.jsse.easysec.tls.TlsCredentialedSigner;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.TrustedAuthority;
import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedDecryptor;
import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import javax.security.auth.x500.X500Principal;

abstract class JsseUtils {
    private static final boolean provTlsAllowLegacyMasterSecret = PropertyUtils.getBooleanSystemProperty("jdk.tls.allowLegacyMasterSecret", true);
    private static final boolean provTlsAllowLegacyResumption = PropertyUtils.getBooleanSystemProperty("jdk.tls.allowLegacyResumption", false);
    private static final int provTlsMaxCertificateChainLength = PropertyUtils.getIntegerSystemProperty("jdk.tls.maxCertificateChainLength", 10, 1, 2147483647);
    private static final int provTlsMaxHandshakeMessageSize = PropertyUtils.getIntegerSystemProperty("jdk.tls.maxHandshakeMessageSize", 32768, 1024, 2147483647);
    private static final boolean provTlsRequireCloseNotify = PropertyUtils.getBooleanSystemProperty("com.sun.net.ssl.requireCloseNotify", true);
    private static final boolean provTlsUseExtendedMasterSecret = PropertyUtils.getBooleanSystemProperty("jdk.tls.useExtendedMasterSecret", true);
    static final Set<BCCryptoPrimitive> KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;
    static final Set<BCCryptoPrimitive> KEY_ENCAPSULATION_CRYPTO_PRIMITIVES_BC;
    static final Set<BCCryptoPrimitive> SIGNATURE_CRYPTO_PRIMITIVES_BC;
    static String EMPTY_STRING;
    static X509Certificate[] EMPTY_X509CERTIFICATES;

    JsseUtils() {
    }

    static boolean allowLegacyMasterSecret() {
        return provTlsAllowLegacyMasterSecret;
    }

    static boolean allowLegacyResumption() {
        return provTlsAllowLegacyResumption;
    }

    static String getSignatureAlgorithmsReport(String title, List<SignatureSchemeInfo> signatureSchemes) {
        String[] names = SignatureSchemeInfo.getJcaSignatureAlgorithmsBC(signatureSchemes);
        StringBuilder sb = new StringBuilder(title);
        sb.append(':');
        String[] var4 = names;
        int var5 = names.length;

        for(int var6 = 0; var6 < var5; ++var6) {
            String name = var4[var6];
            sb.append(' ');
            sb.append(name);
        }

        return sb.toString();
    }

    static void checkSessionCreationEnabled(ProvTlsManager manager) {
        if (!manager.getEnableSessionCreation()) {
            throw new IllegalStateException("Cannot resume session and session creation is disabled");
        }
    }

    static <T> T[] clone(T[] ts) {
        return null == ts ? null : (T[]) ts.clone();
    }

    static boolean contains(String[] values, String value) {
        for(int i = 0; i < values.length; ++i) {
            if (value.equals(values[i])) {
                return true;
            }
        }

        return false;
    }

    static <T> boolean containsNull(T[] ts) {
        for(int i = 0; i < ts.length; ++i) {
            if (null == ts[i]) {
                return true;
            }
        }

        return false;
    }

    static String[] copyOf(String[] data, int newLength) {
        String[] tmp = new String[newLength];
        System.arraycopy(data, 0, tmp, 0, Math.min(data.length, newLength));
        return tmp;
    }

    static TlsCredentialedDecryptor createCredentialedDecryptor(JcaTlsCrypto crypto, BCX509Key x509Key) {
        PrivateKey privateKey = x509Key.getPrivateKey();
        Certificate certificate = getCertificateMessage(crypto, x509Key.getCertificateChain());
        return new JceDefaultTlsCredentialedDecryptor(crypto, certificate, privateKey);
    }

    static TlsCredentialedSigner createCredentialedSigner(TlsContext context, JcaTlsCrypto crypto, BCX509Key x509Key, SignatureAndHashAlgorithm sigAndHashAlg) {
        TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);
        PrivateKey privateKey = x509Key.getPrivateKey();
        Certificate certificate = getCertificateMessage(crypto, x509Key.getCertificateChain());
        return new JcaDefaultTlsCredentialedSigner(cryptoParams, crypto, privateKey, certificate, sigAndHashAlg);
    }

    static TlsCredentialedSigner createCredentialedSigner13(TlsContext context, JcaTlsCrypto crypto, BCX509Key x509Key, SignatureAndHashAlgorithm sigAndHashAlg, byte[] certificateRequestContext) {
        TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);
        PrivateKey privateKey = x509Key.getPrivateKey();
        Certificate certificate = getCertificateMessage13(crypto, x509Key.getCertificateChain(), certificateRequestContext);
        return new JcaDefaultTlsCredentialedSigner(cryptoParams, crypto, privateKey, certificate, sigAndHashAlg);
    }

    static boolean equals(Object a, Object b) {
        return a == b || null != a && null != b && a.equals(b);
    }

    static int getMaxCertificateChainLength() {
        return provTlsMaxCertificateChainLength;
    }

    static int getMaxHandshakeMessageSize() {
        return provTlsMaxHandshakeMessageSize;
    }

    static ASN1ObjectIdentifier getNamedCurveOID(PublicKey publicKey) {
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            AlgorithmIdentifier algID = spki.getAlgorithm();
            if (X9ObjectIdentifiers.id_ecPublicKey.equals(algID.getAlgorithm())) {
                ASN1Encodable parameters = algID.getParameters();
                if (null != parameters) {
                    ASN1Primitive primitive = parameters.toASN1Primitive();
                    if (primitive instanceof ASN1ObjectIdentifier) {
                        return (ASN1ObjectIdentifier)primitive;
                    }
                }
            }
        } catch (Exception var5) {
        }

        return null;
    }

    static String[] resize(String[] data, int count) {
        if (count < data.length) {
            data = copyOf(data, count);
        }

        return data;
    }

    static String getApplicationProtocol(SecurityParameters securityParameters) {
        if (null != securityParameters && securityParameters.isApplicationProtocolSet()) {
            ProtocolName applicationProtocol = securityParameters.getApplicationProtocol();
            return null == applicationProtocol ? null : applicationProtocol.getUtf8Decoding();
        } else {
            return null;
        }
    }

    static String getAuthTypeServer(int keyExchangeAlgorithm) {
        switch(keyExchangeAlgorithm) {
            case 0:
                return "UNKNOWN";
            case 1:
                return "KE:RSA";
            case 2:
            case 4:
            case 6:
            case 8:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
            case 20:
            case 21:
            default:
                throw new IllegalArgumentException();
            case 3:
                return "DHE_DSS";
            case 5:
                return "DHE_RSA";
            case 7:
                return "DH_DSS";
            case 9:
                return "DH_RSA";
            case 16:
                return "ECDH_ECDSA";
            case 17:
                return "ECDHE_ECDSA";
            case 18:
                return "ECDH_RSA";
            case 19:
                return "ECDHE_RSA";
            case 22:
                return "SRP_DSS";
            case 23:
                return "SRP_RSA";
        }
    }

    static Vector<X500Name> getCertificateAuthorities(BCX509ExtendedTrustManager x509TrustManager) {
        Set<X500Principal> caSubjects = new HashSet();
        X509Certificate[] var2 = x509TrustManager.getAcceptedIssuers();
        int var3 = var2.length;

        for(int var4 = 0; var4 < var3; ++var4) {
            X509Certificate acceptedIssuer = var2[var4];
            if (acceptedIssuer.getBasicConstraints() >= 0) {
                caSubjects.add(acceptedIssuer.getSubjectX500Principal());
            } else {
                caSubjects.add(acceptedIssuer.getIssuerX500Principal());
            }
        }

        if (caSubjects.isEmpty()) {
            return null;
        } else {
            Vector<X500Name> certificateAuthorities = new Vector(caSubjects.size());
            Iterator var7 = caSubjects.iterator();

            while(var7.hasNext()) {
                X500Principal caSubject = (X500Principal)var7.next();
                certificateAuthorities.add(X500Name.getInstance(caSubject.getEncoded()));
            }

            return certificateAuthorities;
        }
    }

    static Certificate getCertificateMessage(JcaTlsCrypto crypto, X509Certificate[] chain) {
        if (TlsUtils.isNullOrEmpty(chain)) {
            throw new IllegalArgumentException();
        } else {
            TlsCertificate[] certificateList = new TlsCertificate[chain.length];

            for(int i = 0; i < chain.length; ++i) {
                certificateList[i] = new JcaTlsCertificate(crypto, chain[i]);
            }

            return new Certificate(certificateList);
        }
    }

    static Certificate getCertificateMessage13(JcaTlsCrypto crypto, X509Certificate[] chain, byte[] certificateRequestContext) {
        if (TlsUtils.isNullOrEmpty(chain)) {
            throw new IllegalArgumentException();
        } else {
            CertificateEntry[] certificateEntryList = new CertificateEntry[chain.length];

            for(int i = 0; i < chain.length; ++i) {
                JcaTlsCertificate certificate = new JcaTlsCertificate(crypto, chain[i]);
                Hashtable<Integer, byte[]> extensions = null;
                certificateEntryList[i] = new CertificateEntry(certificate, (Hashtable)extensions);
            }

            return new Certificate(certificateRequestContext, certificateEntryList);
        }
    }

    static X509Certificate getEndEntity(JcaTlsCrypto crypto, Certificate certificateMessage) throws IOException {
        return certificateMessage != null && !certificateMessage.isEmpty() ? getX509Certificate(crypto, certificateMessage.getCertificateAt(0)) : null;
    }

    static String getJcaSignatureAlgorithmBC(String jcaSignatureAlgorithm, String keyAlgorithm) {
        return !jcaSignatureAlgorithm.endsWith("withRSAandMGF1") ? jcaSignatureAlgorithm : jcaSignatureAlgorithm + ":" + keyAlgorithm;
    }

    static String getKeyType13(String keyAlgorithm, int namedGroup13) {
        return namedGroup13 < 0 ? keyAlgorithm : keyAlgorithm + "/" + NamedGroup.getStandardName(namedGroup13);
    }

    static String getKeyTypeLegacyClient(short clientCertificateType) {
        switch(clientCertificateType) {
            case 1:
                return "RSA";
            case 2:
                return "DSA";
            case 64:
                return "EC";
            default:
                throw new IllegalArgumentException();
        }
    }

    static String getKeyTypeLegacyServer(int keyExchangeAlgorithm) {
        return getAuthTypeServer(keyExchangeAlgorithm);
    }

    static Vector<ProtocolName> getProtocolNames(String[] applicationProtocols) {
        if (TlsUtils.isNullOrEmpty(applicationProtocols)) {
            return null;
        } else {
            Vector<ProtocolName> result = new Vector(applicationProtocols.length);
            String[] var2 = applicationProtocols;
            int var3 = applicationProtocols.length;

            for(int var4 = 0; var4 < var3; ++var4) {
                String applicationProtocol = var2[var4];
                result.add(ProtocolName.asUtf8Encoding(applicationProtocol));
            }

            return result;
        }
    }

    static List<String> getProtocolNames(Vector<ProtocolName> applicationProtocols) {
        if (null != applicationProtocols && !applicationProtocols.isEmpty()) {
            ArrayList<String> result = new ArrayList(applicationProtocols.size());
            Iterator var2 = applicationProtocols.iterator();

            while(var2.hasNext()) {
                ProtocolName applicationProtocol = (ProtocolName)var2.next();
                result.add(applicationProtocol.getUtf8Decoding());
            }

            return result;
        } else {
            return null;
        }
    }

    static byte[] getStatusResponse(OCSPResponse ocspResponse) throws IOException {
        return null == ocspResponse ? TlsUtils.EMPTY_BYTES : ocspResponse.getEncoded("DER");
    }

    static List<byte[]> getStatusResponses(CertificateStatus certificateStatus) throws IOException {
        if (null != certificateStatus) {
            switch(certificateStatus.getStatusType()) {
                case 1:
                    OCSPResponse ocspResponse = certificateStatus.getOCSPResponse();
                    return Collections.singletonList(getStatusResponse(ocspResponse));
                case 2:
                    Vector<OCSPResponse> ocspResponseList = certificateStatus.getOCSPResponseList();
                    int count = ocspResponseList.size();
                    ArrayList<byte[]> statusResponses = new ArrayList(count);

                    for(int i = 0; i < count; ++i) {
                        OCSPResponse ocspResponse1 = (OCSPResponse)ocspResponseList.elementAt(i);
                        statusResponses.add(getStatusResponse(ocspResponse1));
                    }

                    return Collections.unmodifiableList(statusResponses);
            }
        }

        return null;
    }

    static X500Principal[] getTrustedIssuers(Vector<TrustedAuthority> trustedCAKeys) throws IOException {
        if (null != trustedCAKeys && !trustedCAKeys.isEmpty()) {
            int count = trustedCAKeys.size();
            X500Principal[] principals = new X500Principal[count];

            for(int i = 0; i < count; ++i) {
                TrustedAuthority trustedAuthority = (TrustedAuthority)trustedCAKeys.get(i);
                if (2 != trustedAuthority.getIdentifierType()) {
                    return null;
                }

                principals[i] = toX500Principal(trustedAuthority.getX509Name());
            }

            return principals;
        } else {
            return null;
        }
    }

    static X509Certificate getX509Certificate(JcaTlsCrypto crypto, TlsCertificate tlsCertificate) throws IOException {
        return JcaTlsCertificate.convert(crypto, tlsCertificate).getX509Certificate();
    }

    static X509Certificate[] getX509CertificateChain(JcaTlsCrypto crypto, Certificate certificateMessage) {
        if (certificateMessage != null && !certificateMessage.isEmpty()) {
            try {
                X509Certificate[] chain = new X509Certificate[certificateMessage.getLength()];

                for(int i = 0; i < chain.length; ++i) {
                    chain[i] = JcaTlsCertificate.convert(crypto, certificateMessage.getCertificateAt(i)).getX509Certificate();
                }

                return chain;
            } catch (IOException var4) {
                throw new RuntimeException(var4);
            }
        } else {
            return EMPTY_X509CERTIFICATES;
        }
    }

    static X509Certificate[] getX509CertificateChain(java.security.cert.Certificate[] chain) {
        if (chain == null) {
            return null;
        } else if (chain instanceof X509Certificate[]) {
            return containsNull(chain) ? null : (X509Certificate[])((X509Certificate[])chain);
        } else {
            X509Certificate[] x509Chain = new X509Certificate[chain.length];

            for(int i = 0; i < chain.length; ++i) {
                java.security.cert.Certificate c = chain[i];
                if (!(c instanceof X509Certificate)) {
                    return null;
                }

                x509Chain[i] = (X509Certificate)c;
            }

            return x509Chain;
        }
    }

    static X500Principal getSubject(JcaTlsCrypto crypto, Certificate certificateMessage) {
        if (certificateMessage != null && !certificateMessage.isEmpty()) {
            try {
                return getX509Certificate(crypto, certificateMessage.getCertificateAt(0)).getSubjectX500Principal();
            } catch (IOException var3) {
                throw new RuntimeException(var3);
            }
        } else {
            return null;
        }
    }

    static String getAlertLogMessage(String root, short alertLevel, short alertDescription) {
        return root + " " + AlertLevel.getText(alertLevel) + " " + AlertDescription.getText(alertDescription) + " alert";
    }

    static String getKeyAlgorithm(Key key) {
        if (key instanceof PrivateKey) {
            return getPrivateKeyAlgorithm((PrivateKey)key);
        } else {
            return key instanceof PublicKey ? getPublicKeyAlgorithm((PublicKey)key) : key.getAlgorithm();
        }
    }

    static String getPrivateKeyAlgorithm(PrivateKey privateKey) {
        String algorithm = privateKey.getAlgorithm();
        if ("RSA".equalsIgnoreCase(algorithm)) {
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(privateKey.getEncoded());
            if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(pki.getPrivateKeyAlgorithm().getAlgorithm())) {
                return "RSASSA-PSS";
            }
        }

        return algorithm;
    }

    static String getPublicKeyAlgorithm(PublicKey publicKey) {
        String algorithm = publicKey.getAlgorithm();
        if ("RSA".equalsIgnoreCase(algorithm)) {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(spki.getAlgorithm().getAlgorithm())) {
                return "RSASSA-PSS";
            }
        }

        return algorithm;
    }

    static boolean isNameSpecified(String name) {
        return !isNullOrEmpty(name);
    }

    static boolean isNullOrEmpty(String s) {
        return null == s || s.length() < 1;
    }

    static boolean isTLSv12(String protocol) {
        ProtocolVersion protocolVersion = ProvSSLContextSpi.getProtocolVersion(protocol);
        return null != protocolVersion && TlsUtils.isTLSv12(protocolVersion);
    }

    static boolean isTLSv13(String protocol) {
        ProtocolVersion protocolVersion = ProvSSLContextSpi.getProtocolVersion(protocol);
        return null != protocolVersion && TlsUtils.isTLSv13(protocolVersion);
    }

    static X500Principal toX500Principal(X500Name name) throws IOException {
        return null == name ? null : new X500Principal(name.getEncoded("DER"));
    }

    static X500Principal[] toX500Principals(Vector<X500Name> names) throws IOException {
        if (null == names) {
            return null;
        } else {
            Set<X500Principal> principals = new LinkedHashSet();
            int count = names.size();

            for(int i = 0; i < count; ++i) {
                X500Principal principal = toX500Principal((X500Name)names.get(i));
                if (null != principal) {
                    principals.add(principal);
                }
            }

            return (X500Principal[])principals.toArray(new X500Principal[0]);
        }
    }

    static BCSNIServerName convertSNIServerName(ServerName serverName) {
        short nameType = serverName.getNameType();
        byte[] nameData = serverName.getNameData();
        switch(nameType) {
            case 0:
                return new BCSNIHostName(nameData);
            default:
                return new JsseUtils.BCUnknownServerName(nameType, nameData);
        }
    }

    static List<BCSNIServerName> convertSNIServerNames(Vector<ServerName> serverNameList) {
        if (null != serverNameList && !serverNameList.isEmpty()) {
            ArrayList<BCSNIServerName> result = new ArrayList(serverNameList.size());
            Enumeration serverNames = serverNameList.elements();

            while(serverNames.hasMoreElements()) {
                result.add(convertSNIServerName((ServerName)serverNames.nextElement()));
            }

            return Collections.unmodifiableList(result);
        } else {
            return Collections.emptyList();
        }
    }

    static BCSNIServerName findMatchingSNIServerName(Vector<ServerName> serverNameList, Collection<BCSNIMatcher> sniMatchers) {
        if (!serverNameList.isEmpty()) {
            List<BCSNIServerName> sniServerNames = convertSNIServerNames(serverNameList);
            Iterator var3 = sniMatchers.iterator();

            while(true) {
                while(true) {
                    BCSNIMatcher sniMatcher;
                    do {
                        if (!var3.hasNext()) {
                            return null;
                        }

                        sniMatcher = (BCSNIMatcher)var3.next();
                    } while(null == sniMatcher);

                    int nameType = sniMatcher.getType();
                    Iterator var6 = sniServerNames.iterator();

                    while(var6.hasNext()) {
                        BCSNIServerName sniServerName = (BCSNIServerName)var6.next();
                        if (null != sniServerName && sniServerName.getType() == nameType) {
                            if (sniMatcher.matches(sniServerName)) {
                                return sniServerName;
                            }
                            break;
                        }
                    }
                }
            }
        } else {
            return null;
        }
    }

    static BCSNIHostName getSNIHostName(List<BCSNIServerName> serverNames) {
        if (null != serverNames) {
            Iterator var1 = serverNames.iterator();

            while(var1.hasNext()) {
                BCSNIServerName serverName = (BCSNIServerName)var1.next();
                if (null != serverName && 0 == serverName.getType()) {
                    if (serverName instanceof BCSNIHostName) {
                        return (BCSNIHostName)serverName;
                    }

                    try {
                        return new BCSNIHostName(serverName.getEncoded());
                    } catch (RuntimeException var4) {
                        return null;
                    }
                }
            }
        }

        return null;
    }

    static String removeAllWhitespace(String s) {
        if (isNullOrEmpty(s)) {
            return s;
        } else {
            int originalLength = s.length();
            char[] buf = new char[originalLength];
            int bufPos = 0;

            for(int i = 0; i < originalLength; ++i) {
                char c = s.charAt(i);
                if (!Character.isWhitespace(c)) {
                    buf[bufPos++] = c;
                }
            }

            if (bufPos == 0) {
                return EMPTY_STRING;
            } else if (bufPos == originalLength) {
                return s;
            } else {
                return new String(buf, 0, bufPos);
            }
        }
    }

    static boolean requireCloseNotify() {
        return provTlsRequireCloseNotify;
    }

    static String stripDoubleQuotes(String s) {
        return stripOuterChars(s, '"', '"');
    }

    static String stripSquareBrackets(String s) {
        return stripOuterChars(s, '[', ']');
    }

    private static String stripOuterChars(String s, char openChar, char closeChar) {
        if (s != null) {
            int sLast = s.length() - 1;
            if (sLast > 0 && s.charAt(0) == openChar && s.charAt(sLast) == closeChar) {
                return s.substring(1, sLast);
            }
        }

        return s;
    }

    static boolean useExtendedMasterSecret() {
        return provTlsUseExtendedMasterSecret;
    }

    static {
        KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC = Collections.unmodifiableSet(EnumSet.of(BCCryptoPrimitive.KEY_AGREEMENT));
        KEY_ENCAPSULATION_CRYPTO_PRIMITIVES_BC = Collections.unmodifiableSet(EnumSet.of(BCCryptoPrimitive.KEY_ENCAPSULATION));
        SIGNATURE_CRYPTO_PRIMITIVES_BC = Collections.unmodifiableSet(EnumSet.of(BCCryptoPrimitive.SIGNATURE));
        EMPTY_STRING = "";
        EMPTY_X509CERTIFICATES = new X509Certificate[0];
    }

    static class BCUnknownServerName extends BCSNIServerName {
        BCUnknownServerName(int nameType, byte[] encoded) {
            super(nameType, encoded);
        }
    }
}
