package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jsse.BCX509ExtendedKeyManager;
import com.mi.car.jsse.easysec.jsse.BCX509ExtendedTrustManager;
import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.jsse.java.security.BCCryptoPrimitive;
import com.mi.car.jsse.easysec.tls.CipherSuite;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.TlsDHUtils;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

import java.security.AlgorithmParameters;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

class ProvSSLContextSpi extends SSLContextSpi {
    private static final Logger LOG = Logger.getLogger(ProvSSLContextSpi.class.getName());
    private static final String PROPERTY_CLIENT_CIPHERSUITES = "jdk.tls.client.cipherSuites";
    private static final String PROPERTY_SERVER_CIPHERSUITES = "jdk.tls.server.cipherSuites";
    private static final String PROPERTY_CLIENT_PROTOCOLS = "jdk.tls.client.protocols";
    private static final String PROPERTY_SERVER_PROTOCOLS = "jdk.tls.server.protocols";
    private static final Set<BCCryptoPrimitive> TLS_CRYPTO_PRIMITIVES_BC;
    private static final Map<String, CipherSuiteInfo> SUPPORTED_CIPHERSUITE_MAP;
    private static final Map<String, CipherSuiteInfo> SUPPORTED_CIPHERSUITE_MAP_FIPS;
    private static final Map<String, ProtocolVersion> SUPPORTED_PROTOCOL_MAP;
    private static final Map<String, ProtocolVersion> SUPPORTED_PROTOCOL_MAP_FIPS;
    private static final List<String> DEFAULT_CIPHERSUITE_LIST;
    private static final List<String> DEFAULT_CIPHERSUITE_LIST_FIPS;
    private static final List<String> DEFAULT_PROTOCOL_LIST;
    private static final List<String> DEFAULT_PROTOCOL_LIST_FIPS;
    protected final boolean isInFipsMode;
    protected final JcaTlsCryptoProvider cryptoProvider;
    protected final Map<String, CipherSuiteInfo> supportedCipherSuites;
    protected final Map<String, ProtocolVersion> supportedProtocols;
    protected final String[] defaultCipherSuitesClient;
    protected final String[] defaultCipherSuitesServer;
    protected final String[] defaultProtocolsClient;
    protected final String[] defaultProtocolsServer;
    private ContextData contextData = null;

    private static void addCipherSuite(Map<String, CipherSuiteInfo> cs, String name, int cipherSuite) {
        CipherSuiteInfo cipherSuiteInfo = CipherSuiteInfo.forCipherSuite(cipherSuite, name);
        if (null != cs.put(name, cipherSuiteInfo)) {
            throw new IllegalStateException("Duplicate names in supported-cipher-suites");
        }
    }

    private static List<String> createDefaultCipherSuiteList(Set<String> supportedCipherSuiteSet) {
        ArrayList<String> cs = new ArrayList();
        cs.add("TLS_CHACHA20_POLY1305_SHA256");
        cs.add("TLS_AES_256_GCM_SHA384");
        cs.add("TLS_AES_128_GCM_SHA256");
        cs.add("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        cs.add("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        cs.add("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
        cs.add("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
        cs.add("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
        cs.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");
        cs.add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA");
        cs.add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
        cs.add("TLS_RSA_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_RSA_WITH_AES_128_GCM_SHA256");
        cs.add("TLS_RSA_WITH_AES_256_CBC_SHA256");
        cs.add("TLS_RSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_RSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_RSA_WITH_AES_128_CBC_SHA");
        cs.retainAll(supportedCipherSuiteSet);
        cs.trimToSize();
        return Collections.unmodifiableList(cs);
    }

    private static List<String> createDefaultCipherSuiteListFips(List<String> defaultCipherSuiteList) {
        ArrayList<String> cs = new ArrayList(defaultCipherSuiteList);
        FipsUtils.removeNonFipsCipherSuites(cs);
        cs.trimToSize();
        return Collections.unmodifiableList(cs);
    }

    private static List<String> createDefaultProtocolList(Set<String> supportedProtocolSet) {
        ArrayList<String> ps = new ArrayList();
        ps.add("TLSv1.2");
        ps.add("TLSv1.1");
        ps.add("TLSv1");
        ps.retainAll(supportedProtocolSet);
        ps.trimToSize();
        return Collections.unmodifiableList(ps);
    }

    private static List<String> createDefaultProtocolListFips(List<String> defaultProtocolList) {
        ArrayList<String> ps = new ArrayList(defaultProtocolList);
        FipsUtils.removeNonFipsProtocols(ps);
        ps.trimToSize();
        return Collections.unmodifiableList(ps);
    }

    private static Map<String, CipherSuiteInfo> createSupportedCipherSuiteMap() {
        Map<String, CipherSuiteInfo> cs = new TreeMap();
        addCipherSuite(cs, "TLS_AES_128_CCM_8_SHA256", 4869);
        addCipherSuite(cs, "TLS_AES_128_CCM_SHA256", 4868);
        addCipherSuite(cs, "TLS_AES_128_GCM_SHA256", 4865);
        addCipherSuite(cs, "TLS_AES_256_GCM_SHA384", 4866);
        addCipherSuite(cs, "TLS_CHACHA20_POLY1305_SHA256", 4867);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", 19);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", 50);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", 64);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", 162);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", 56);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", 106);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", 163);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", 49218);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", 49238);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", 49219);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", 49239);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", 68);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", 189);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256", 49280);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", 135);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", 195);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384", 49281);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 22);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 51);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 103);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_128_CCM", 49310);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_128_CCM_8", 49314);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 158);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 57);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 107);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_256_CCM", 49311);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_256_CCM_8", 49315);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 159);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", 49220);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", 49234);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", 49221);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", 49235);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", 69);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", 190);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", 49276);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", 136);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", 196);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", 49277);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 52394);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 49160);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 49161);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 49187);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", 49324);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", 49326);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 49195);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 49162);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 49188);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", 49325);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", 49327);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 49196);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", 49224);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", 49244);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", 49225);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", 49245);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", 49266);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", 49286);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", 49267);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", 49287);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 52393);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", 49158);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 49170);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 49171);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 49191);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 49199);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 49172);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 49192);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 49200);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", 49228);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", 49248);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", 49229);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", 49249);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", 49270);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", 49290);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", 49271);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", 49291);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 52392);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_NULL_SHA", 49168);
        addCipherSuite(cs, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 10);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_128_CBC_SHA", 47);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_128_CBC_SHA256", 60);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_128_CCM", 49308);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_128_CCM_8", 49312);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_128_GCM_SHA256", 156);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_256_CBC_SHA", 53);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_256_CBC_SHA256", 61);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_256_CCM", 49309);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_256_CCM_8", 49313);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_256_GCM_SHA384", 157);
        addCipherSuite(cs, "TLS_RSA_WITH_ARIA_128_CBC_SHA256", 49212);
        addCipherSuite(cs, "TLS_RSA_WITH_ARIA_128_GCM_SHA256", 49232);
        addCipherSuite(cs, "TLS_RSA_WITH_ARIA_256_CBC_SHA384", 49213);
        addCipherSuite(cs, "TLS_RSA_WITH_ARIA_256_GCM_SHA384", 49233);
        addCipherSuite(cs, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 65);
        addCipherSuite(cs, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", 186);
        addCipherSuite(cs, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", 49274);
        addCipherSuite(cs, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", 132);
        addCipherSuite(cs, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", 192);
        addCipherSuite(cs, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", 49275);
        addCipherSuite(cs, "TLS_RSA_WITH_NULL_SHA", 2);
        addCipherSuite(cs, "TLS_RSA_WITH_NULL_SHA256", 59);
        return Collections.unmodifiableMap(cs);
    }

    private static Map<String, CipherSuiteInfo> createSupportedCipherSuiteMapFips(Map<String, CipherSuiteInfo> supportedCipherSuiteMap) {
        Map<String, CipherSuiteInfo> cs = new LinkedHashMap(supportedCipherSuiteMap);
        FipsUtils.removeNonFipsCipherSuites(cs.keySet());
        return Collections.unmodifiableMap(cs);
    }

    private static Map<String, ProtocolVersion> createSupportedProtocolMap() {
        Map<String, ProtocolVersion> ps = new LinkedHashMap();
        ps.put("TLSv1.3", ProtocolVersion.TLSv13);
        ps.put("TLSv1.2", ProtocolVersion.TLSv12);
        ps.put("TLSv1.1", ProtocolVersion.TLSv11);
        ps.put("TLSv1", ProtocolVersion.TLSv10);
        ps.put("SSLv3", ProtocolVersion.SSLv3);
        return Collections.unmodifiableMap(ps);
    }

    private static Map<String, ProtocolVersion> createSupportedProtocolMapFips(Map<String, ProtocolVersion> supportedProtocolMap) {
        Map<String, ProtocolVersion> ps = new LinkedHashMap(supportedProtocolMap);
        FipsUtils.removeNonFipsProtocols(ps.keySet());
        return Collections.unmodifiableMap(ps);
    }

    private static String[] getDefaultEnabledCipherSuites(Map<String, CipherSuiteInfo> supportedCipherSuiteMap, List<String> defaultCipherSuiteList, boolean disableDHDefaultSuites, String cipherSuitesPropertyName) {
        List<String> candidates = getJdkTlsCipherSuites(cipherSuitesPropertyName, defaultCipherSuiteList);
        String[] result = new String[candidates.size()];
        int count = 0;
        Iterator var7 = candidates.iterator();

        while(true) {
            String candidate;
            CipherSuiteInfo cipherSuiteInfo;
            do {
                do {
                    if (!var7.hasNext()) {
                        return JsseUtils.resize(result, count);
                    }

                    candidate = (String)var7.next();
                    cipherSuiteInfo = (CipherSuiteInfo)supportedCipherSuiteMap.get(candidate);
                } while(null == cipherSuiteInfo);
            } while(disableDHDefaultSuites && candidates == defaultCipherSuiteList && TlsDHUtils.isDHCipherSuite(cipherSuiteInfo.getCipherSuite()));

            if (ProvAlgorithmConstraints.DEFAULT.permits(TLS_CRYPTO_PRIMITIVES_BC, candidate, (AlgorithmParameters)null)) {
                result[count++] = candidate;
            }
        }
    }

    private static String[] getDefaultEnabledCipherSuitesClient(Map<String, CipherSuiteInfo> supportedCipherSuiteMap, List<String> defaultCipherSuiteList) {
        boolean disableDHDefaultSuites = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.client.dh.disableDefaultSuites", false);
        return getDefaultEnabledCipherSuites(supportedCipherSuiteMap, defaultCipherSuiteList, disableDHDefaultSuites, "jdk.tls.client.cipherSuites");
    }

    private static String[] getDefaultEnabledCipherSuitesServer(Map<String, CipherSuiteInfo> supportedCipherSuiteMap, List<String> defaultCipherSuiteList) {
        boolean disableDHDefaultSuites = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.server.dh.disableDefaultSuites", false);
        return getDefaultEnabledCipherSuites(supportedCipherSuiteMap, defaultCipherSuiteList, disableDHDefaultSuites, "jdk.tls.server.cipherSuites");
    }

    private static String[] getDefaultEnabledProtocols(Map<String, ProtocolVersion> supportedProtocolMap, String protocolsPropertyName, List<String> defaultProtocolList, List<String> specifiedProtocols) {
        List<String> candidates = specifiedProtocols;
        if (null == specifiedProtocols) {
            candidates = getJdkTlsProtocols(protocolsPropertyName, defaultProtocolList);
        }

        String[] result = new String[candidates.size()];
        int count = 0;
        Iterator var7 = candidates.iterator();

        while(var7.hasNext()) {
            String candidate = (String)var7.next();
            if (supportedProtocolMap.containsKey(candidate) && ProvAlgorithmConstraints.DEFAULT_TLS_ONLY.permits(TLS_CRYPTO_PRIMITIVES_BC, candidate, (AlgorithmParameters)null)) {
                result[count++] = candidate;
            }
        }

        return JsseUtils.resize(result, count);
    }

    private static String[] getDefaultEnabledProtocolsClient(Map<String, ProtocolVersion> supportedProtocolMap, List<String> defaultProtocolList, List<String> specifiedProtocols) {
        return getDefaultEnabledProtocols(supportedProtocolMap, "jdk.tls.client.protocols", defaultProtocolList, specifiedProtocols);
    }

    private static String[] getDefaultEnabledProtocolsServer(Map<String, ProtocolVersion> supportedProtocolMap, List<String> defaultProtocolList) {
        return getDefaultEnabledProtocols(supportedProtocolMap, "jdk.tls.server.protocols", defaultProtocolList, (List)null);
    }

    private static List<String> getJdkTlsCipherSuites(String cipherSuitesPropertyName, List<String> defaultCipherSuiteList) {
        String[] cipherSuites = PropertyUtils.getStringArraySystemProperty(cipherSuitesPropertyName);
        if (null == cipherSuites) {
            return defaultCipherSuiteList;
        } else {
            ArrayList<String> result = new ArrayList(cipherSuites.length);
            String[] var4 = cipherSuites;
            int var5 = cipherSuites.length;

            for(int var6 = 0; var6 < var5; ++var6) {
                String cipherSuite = var4[var6];
                if (!result.contains(cipherSuite)) {
                    if (!SUPPORTED_CIPHERSUITE_MAP.containsKey(cipherSuite)) {
                        LOG.warning("'" + cipherSuitesPropertyName + "' contains unsupported cipher suite: " + cipherSuite);
                    } else {
                        result.add(cipherSuite);
                    }
                }
            }

            if (result.isEmpty()) {
                LOG.severe("'" + cipherSuitesPropertyName + "' contained no supported cipher suites (ignoring)");
                return defaultCipherSuiteList;
            } else {
                return result;
            }
        }
    }

    private static List<String> getJdkTlsProtocols(String protocolsPropertyName, List<String> defaultProtocolList) {
        String[] protocols = PropertyUtils.getStringArraySystemProperty(protocolsPropertyName);
        if (null == protocols) {
            return defaultProtocolList;
        } else {
            ArrayList<String> result = new ArrayList(protocols.length);
            String[] var4 = protocols;
            int var5 = protocols.length;

            for(int var6 = 0; var6 < var5; ++var6) {
                String protocol = var4[var6];
                if (!result.contains(protocol)) {
                    if (!SUPPORTED_PROTOCOL_MAP.containsKey(protocol)) {
                        LOG.warning("'" + protocolsPropertyName + "' contains unsupported protocol: " + protocol);
                    } else {
                        result.add(protocol);
                    }
                }
            }

            if (result.isEmpty()) {
                LOG.severe("'" + protocolsPropertyName + "' contained no supported protocols (ignoring)");
                return defaultProtocolList;
            } else {
                return result;
            }
        }
    }

    private static String[] getArray(Collection<String> c) {
        return (String[])c.toArray(new String[c.size()]);
    }

    private static String[] getKeysArray(Map<String, ?> m) {
        return getArray(m.keySet());
    }

    static CipherSuiteInfo getCipherSuiteInfo(String cipherSuiteName) {
        return (CipherSuiteInfo)SUPPORTED_CIPHERSUITE_MAP.get(cipherSuiteName);
    }

    static String getCipherSuiteName(int cipherSuite) {
        if (0 == cipherSuite) {
            return "SSL_NULL_WITH_NULL_NULL";
        } else {
            if (TlsUtils.isValidUint16(cipherSuite)) {
                Iterator var1 = SUPPORTED_CIPHERSUITE_MAP.values().iterator();

                while(var1.hasNext()) {
                    CipherSuiteInfo cipherSuiteInfo = (CipherSuiteInfo)var1.next();
                    if (cipherSuiteInfo.getCipherSuite() == cipherSuite) {
                        return cipherSuiteInfo.getName();
                    }
                }
            }

            return null;
        }
    }

    static KeyManager[] getDefaultKeyManagers() throws Exception {
        KeyStoreConfig keyStoreConfig = ProvKeyManagerFactorySpi.getDefaultKeyStore();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStoreConfig.keyStore, keyStoreConfig.password);
        return kmf.getKeyManagers();
    }

    static TrustManager[] getDefaultTrustManagers() throws Exception {
        KeyStore trustStore = ProvTrustManagerFactorySpi.getDefaultTrustStore();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        return tmf.getTrustManagers();
    }

    static ProtocolVersion getProtocolVersion(String protocolVersionName) {
        return (ProtocolVersion)SUPPORTED_PROTOCOL_MAP.get(protocolVersionName);
    }

    static String getProtocolVersionName(ProtocolVersion protocolVersion) {
        if (null != protocolVersion) {
            Iterator var1 = SUPPORTED_PROTOCOL_MAP.entrySet().iterator();

            while(var1.hasNext()) {
                Map.Entry<String, ProtocolVersion> entry = (Map.Entry)var1.next();
                if (((ProtocolVersion)entry.getValue()).equals(protocolVersion)) {
                    return (String)entry.getKey();
                }
            }
        }

        return "NONE";
    }

    ProvSSLContextSpi(boolean isInFipsMode, JcaTlsCryptoProvider cryptoProvider, List<String> specifiedProtocolsClient) {
        this.isInFipsMode = isInFipsMode;
        this.cryptoProvider = cryptoProvider;
        this.supportedCipherSuites = isInFipsMode ? SUPPORTED_CIPHERSUITE_MAP_FIPS : SUPPORTED_CIPHERSUITE_MAP;
        this.supportedProtocols = isInFipsMode ? SUPPORTED_PROTOCOL_MAP_FIPS : SUPPORTED_PROTOCOL_MAP;
        List<String> defaultCipherSuiteList = isInFipsMode ? DEFAULT_CIPHERSUITE_LIST_FIPS : DEFAULT_CIPHERSUITE_LIST;
        List<String> defaultProtocolList = isInFipsMode ? DEFAULT_PROTOCOL_LIST_FIPS : DEFAULT_PROTOCOL_LIST;
        this.defaultCipherSuitesClient = getDefaultEnabledCipherSuitesClient(this.supportedCipherSuites, defaultCipherSuiteList);
        this.defaultCipherSuitesServer = getDefaultEnabledCipherSuitesServer(this.supportedCipherSuites, defaultCipherSuiteList);
        this.defaultProtocolsClient = getDefaultEnabledProtocolsClient(this.supportedProtocols, defaultProtocolList, specifiedProtocolsClient);
        this.defaultProtocolsServer = getDefaultEnabledProtocolsServer(this.supportedProtocols, defaultProtocolList);
    }

    int[] getActiveCipherSuites(JcaTlsCrypto crypto, ProvSSLParameters sslParameters, ProtocolVersion[] activeProtocolVersions) {
        String[] enabledCipherSuites = sslParameters.getCipherSuitesArray();
        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();
        ProtocolVersion latest = ProtocolVersion.getLatestTLS(activeProtocolVersions);
        ProtocolVersion earliest = ProtocolVersion.getEarliestTLS(activeProtocolVersions);
        boolean post13Active = TlsUtils.isTLSv13(latest);
        boolean pre13Active = !TlsUtils.isTLSv13(earliest);
        int[] candidates = new int[enabledCipherSuites.length];
        int count = 0;
        String[] var12 = enabledCipherSuites;
        int var13 = enabledCipherSuites.length;

        for(int var14 = 0; var14 < var13; ++var14) {
            String enabledCipherSuite = var12[var14];
            CipherSuiteInfo candidate = (CipherSuiteInfo)this.supportedCipherSuites.get(enabledCipherSuite);
            if (null != candidate) {
                if (candidate.isTLSv13()) {
                    if (!post13Active) {
                        continue;
                    }
                } else if (!pre13Active) {
                    continue;
                }

                if (algorithmConstraints.permits(TLS_CRYPTO_PRIMITIVES_BC, enabledCipherSuite, (AlgorithmParameters)null)) {
                    candidates[count++] = candidate.getCipherSuite();
                }
            }
        }

        int[] result = TlsUtils.getSupportedCipherSuites(crypto, candidates, 0, count);
        if (result.length < 1) {
            throw new IllegalStateException("No usable cipher suites enabled");
        } else {
            return result;
        }
    }

    ProtocolVersion[] getActiveProtocolVersions(ProvSSLParameters sslParameters) {
        String[] enabledProtocols = sslParameters.getProtocolsArray();
        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();
        SortedSet<ProtocolVersion> result = new TreeSet(new Comparator<ProtocolVersion>() {
            public int compare(ProtocolVersion o1, ProtocolVersion o2) {
                return o1.isLaterVersionOf(o2) ? -1 : (o2.isLaterVersionOf(o1) ? 1 : 0);
            }
        });
        String[] var5 = enabledProtocols;
        int var6 = enabledProtocols.length;

        for(int var7 = 0; var7 < var6; ++var7) {
            String enabledProtocol = var5[var7];
            ProtocolVersion candidate = (ProtocolVersion)this.supportedProtocols.get(enabledProtocol);
            if (null != candidate && algorithmConstraints.permits(TLS_CRYPTO_PRIMITIVES_BC, enabledProtocol, (AlgorithmParameters)null)) {
                result.add(candidate);
            }
        }

        if (result.isEmpty()) {
            throw new IllegalStateException("No usable protocols enabled");
        } else {
            return (ProtocolVersion[])result.toArray(new ProtocolVersion[result.size()]);
        }
    }

    String[] getDefaultCipherSuites(boolean isClient) {
        return (String[])this.implGetDefaultCipherSuites(isClient).clone();
    }

    String[] getDefaultProtocols(boolean isClient) {
        return (String[])this.implGetDefaultProtocols(isClient).clone();
    }

    ProvSSLParameters getDefaultSSLParameters(boolean isClient) {
        return new ProvSSLParameters(this, this.implGetDefaultCipherSuites(isClient), this.implGetDefaultProtocols(isClient));
    }

    String[] getSupportedCipherSuites() {
        return getKeysArray(this.supportedCipherSuites);
    }

    String[] getSupportedCipherSuites(String[] cipherSuites) {
        if (null == cipherSuites) {
            throw new NullPointerException("'cipherSuites' cannot be null");
        } else {
            ArrayList<String> result = new ArrayList(cipherSuites.length);
            String[] var3 = cipherSuites;
            int var4 = cipherSuites.length;

            for(int var5 = 0; var5 < var4; ++var5) {
                String cipherSuite = var3[var5];
                if (TlsUtils.isNullOrEmpty(cipherSuite)) {
                    throw new IllegalArgumentException("'cipherSuites' cannot contain null or empty string elements");
                }

                if (this.supportedCipherSuites.containsKey(cipherSuite)) {
                    result.add(cipherSuite);
                }
            }

            return getArray(result);
        }
    }

    String[] getSupportedProtocols() {
        return getKeysArray(this.supportedProtocols);
    }

    ProvSSLParameters getSupportedSSLParameters(boolean isClient) {
        return new ProvSSLParameters(this, this.getSupportedCipherSuites(), this.getSupportedProtocols());
    }

    boolean isFips() {
        return this.isInFipsMode;
    }

    boolean isSupportedProtocols(String[] protocols) {
        if (protocols == null) {
            return false;
        } else {
            String[] var2 = protocols;
            int var3 = protocols.length;

            for(int var4 = 0; var4 < var3; ++var4) {
                String protocol = var2[var4];
                if (protocol == null || !this.supportedProtocols.containsKey(protocol)) {
                    return false;
                }
            }

            return true;
        }
    }

    void updateDefaultSSLParameters(ProvSSLParameters sslParameters, boolean isClient) {
        if (sslParameters.getCipherSuitesArray() == this.implGetDefaultCipherSuites(!isClient)) {
            sslParameters.setCipherSuitesArray(this.implGetDefaultCipherSuites(isClient));
        }

        if (sslParameters.getProtocolsArray() == this.implGetDefaultProtocols(!isClient)) {
            sslParameters.setProtocolsArray(this.implGetDefaultProtocols(isClient));
        }

    }

    String validateNegotiatedCipherSuite(ProvSSLParameters sslParameters, int cipherSuite) {
        String name = getCipherSuiteName(cipherSuite);
        if (null != name && JsseUtils.contains(sslParameters.getCipherSuitesArray(), name) && sslParameters.getAlgorithmConstraints().permits(TLS_CRYPTO_PRIMITIVES_BC, name, (AlgorithmParameters)null) && this.supportedCipherSuites.containsKey(name) && (!this.isInFipsMode || FipsUtils.isFipsCipherSuite(name))) {
            return name;
        } else {
            throw new IllegalStateException("SSL connection negotiated unsupported ciphersuite: " + cipherSuite);
        }
    }

    String validateNegotiatedProtocol(ProvSSLParameters sslParameters, ProtocolVersion protocol) {
        String name = getProtocolVersionName(protocol);
        if (null != name && JsseUtils.contains(sslParameters.getProtocolsArray(), name) && sslParameters.getAlgorithmConstraints().permits(TLS_CRYPTO_PRIMITIVES_BC, name, (AlgorithmParameters)null) && this.supportedProtocols.containsKey(name) && (!this.isInFipsMode || FipsUtils.isFipsProtocol(name))) {
            return name;
        } else {
            throw new IllegalStateException("SSL connection negotiated unsupported protocol: " + protocol);
        }
    }

    protected synchronized SSLEngine engineCreateSSLEngine() {
        return SSLEngineUtil.create(this.getContextData());
    }

    protected synchronized SSLEngine engineCreateSSLEngine(String host, int port) {
        return SSLEngineUtil.create(this.getContextData(), host, port);
    }

    protected synchronized SSLSessionContext engineGetClientSessionContext() {
        return this.getContextData().getClientSessionContext();
    }

    protected synchronized SSLSessionContext engineGetServerSessionContext() {
        return this.getContextData().getServerSessionContext();
    }

    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return new ProvSSLServerSocketFactory(this.getContextData());
    }

    protected SSLSocketFactory engineGetSocketFactory() {
        return new ProvSSLSocketFactory(this.getContextData());
    }

    protected SSLParameters engineGetDefaultSSLParameters() {
        this.getContextData();
        return SSLParametersUtil.getSSLParameters(this.getDefaultSSLParameters(true));
    }

    protected SSLParameters engineGetSupportedSSLParameters() {
        this.getContextData();
        return SSLParametersUtil.getSSLParameters(this.getSupportedSSLParameters(true));
    }

    protected synchronized void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        this.contextData = null;
        JcaTlsCrypto crypto = this.cryptoProvider.create(sr);
        JcaJceHelper helper = crypto.getHelper();
        BCX509ExtendedKeyManager x509KeyManager = this.selectX509KeyManager(helper, kms);
        BCX509ExtendedTrustManager x509TrustManager = this.selectX509TrustManager(helper, tms);
        crypto.getSecureRandom().nextInt();
        this.contextData = new ContextData(this, crypto, x509KeyManager, x509TrustManager);
    }

    protected synchronized ContextData getContextData() {
        if (null == this.contextData) {
            throw new IllegalStateException("SSLContext has not been initialized.");
        } else {
            return this.contextData;
        }
    }

    protected BCX509ExtendedKeyManager selectX509KeyManager(JcaJceHelper helper, KeyManager[] kms) throws KeyManagementException {
        if (kms != null) {
            KeyManager[] var3 = kms;
            int var4 = kms.length;

            for(int var5 = 0; var5 < var4; ++var5) {
                KeyManager km = var3[var5];
                if (km instanceof X509KeyManager) {
                    return X509KeyManagerUtil.importX509KeyManager(helper, (X509KeyManager)km);
                }
            }
        }

        return DummyX509KeyManager.INSTANCE;
    }

    protected BCX509ExtendedTrustManager selectX509TrustManager(JcaJceHelper helper, TrustManager[] tms) throws KeyManagementException {
        if (tms == null) {
            try {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init((KeyStore)null);
                tms = tmf.getTrustManagers();
            } catch (Exception var7) {
                LOG.log(Level.WARNING, "Failed to load default trust managers", var7);
            }
        }

        if (tms != null) {
            TrustManager[] var8 = tms;
            int var4 = tms.length;

            for(int var5 = 0; var5 < var4; ++var5) {
                TrustManager tm = var8[var5];
                if (tm instanceof X509TrustManager) {
                    return X509TrustManagerUtil.importX509TrustManager(this.isInFipsMode, helper, (X509TrustManager)tm);
                }
            }
        }

        return DummyX509TrustManager.INSTANCE;
    }

    private String[] implGetDefaultCipherSuites(boolean isClient) {
        return isClient ? this.defaultCipherSuitesClient : this.defaultCipherSuitesServer;
    }

    private String[] implGetDefaultProtocols(boolean isClient) {
        return isClient ? this.defaultProtocolsClient : this.defaultProtocolsServer;
    }

    static {
        TLS_CRYPTO_PRIMITIVES_BC = JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;
        SUPPORTED_CIPHERSUITE_MAP = createSupportedCipherSuiteMap();
        SUPPORTED_CIPHERSUITE_MAP_FIPS = createSupportedCipherSuiteMapFips(SUPPORTED_CIPHERSUITE_MAP);
        SUPPORTED_PROTOCOL_MAP = createSupportedProtocolMap();
        SUPPORTED_PROTOCOL_MAP_FIPS = createSupportedProtocolMapFips(SUPPORTED_PROTOCOL_MAP);
        DEFAULT_CIPHERSUITE_LIST = createDefaultCipherSuiteList(SUPPORTED_CIPHERSUITE_MAP.keySet());
        DEFAULT_CIPHERSUITE_LIST_FIPS = createDefaultCipherSuiteListFips(DEFAULT_CIPHERSUITE_LIST);
        DEFAULT_PROTOCOL_LIST = createDefaultProtocolList(SUPPORTED_PROTOCOL_MAP.keySet());
        DEFAULT_PROTOCOL_LIST_FIPS = createDefaultProtocolListFips(DEFAULT_PROTOCOL_LIST);
    }
}