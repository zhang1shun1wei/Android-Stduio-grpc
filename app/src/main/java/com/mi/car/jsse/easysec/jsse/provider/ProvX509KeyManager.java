package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.KeyPurposeId;
import com.mi.car.jsse.easysec.asn1.x9.ECNamedCurveTable;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jsse.BCExtendedSSLSession;
import com.mi.car.jsse.easysec.jsse.BCSNIHostName;
import com.mi.car.jsse.easysec.jsse.BCX509ExtendedKeyManager;
import com.mi.car.jsse.easysec.jsse.BCX509Key;
import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.tls.NamedGroup;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import java.lang.ref.SoftReference;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLEngine;

class ProvX509KeyManager extends BCX509ExtendedKeyManager {
    private static final Logger LOG = Logger.getLogger(ProvX509KeyManager.class.getName());
    private static final boolean provKeyManagerCheckEKU = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.keyManager.checkEKU", true);
    private final AtomicLong versions = new AtomicLong();
    private final boolean isInFipsMode;
    private final JcaJceHelper helper;
    private final List<KeyStore.Builder> builders;
    private final Map<String, SoftReference<KeyStore.PrivateKeyEntry>> cachedEntries = Collections.synchronizedMap(new LinkedHashMap<String, SoftReference<KeyStore.PrivateKeyEntry>>(16, 0.75F, true) {
        protected boolean removeEldestEntry(Map.Entry<String, SoftReference<KeyStore.PrivateKeyEntry>> eldest) {
            return this.size() > 16;
        }
    });
    private static final Map<String, ProvX509KeyManager.PublicKeyFilter> FILTERS_CLIENT = createFiltersClient();
    private static final Map<String, ProvX509KeyManager.PublicKeyFilter> FILTERS_SERVER = createFiltersServer();

    private static void addECFilter13(Map<String, ProvX509KeyManager.PublicKeyFilter> filters, int namedGroup13) {
        if (!NamedGroup.canBeNegotiated(namedGroup13, ProtocolVersion.TLSv13)) {
            throw new IllegalStateException("Invalid named group for TLS 1.3 EC filter");
        } else {
            String curveName = NamedGroup.getCurveName(namedGroup13);
            if (null != curveName) {
                ASN1ObjectIdentifier standardOID = ECNamedCurveTable.getOID(curveName);
                if (null != standardOID) {
                    String keyType = JsseUtils.getKeyType13("EC", namedGroup13);
                    ProvX509KeyManager.PublicKeyFilter filter = new ProvX509KeyManager.ECPublicKeyFilter13(standardOID);
                    addFilterToMap(filters, keyType, filter);
                    return;
                }
            }

            LOG.warning("Failed to register public key filter for EC with " + NamedGroup.getText(namedGroup13));
        }
    }

    private static void addFilter(Map<String, ProvX509KeyManager.PublicKeyFilter> filters, String keyType) {
        addFilter(filters, 0, keyType, (Class)null, keyType);
    }

    private static void addFilter(Map<String, ProvX509KeyManager.PublicKeyFilter> filters, Class<? extends PublicKey> clazz, String... keyTypes) {
        addFilter(filters, 0, (String)null, clazz, keyTypes);
    }

    private static void addFilter(Map<String, ProvX509KeyManager.PublicKeyFilter> filters, int keyUsageBit, String algorithm, Class<? extends PublicKey> clazz, String... keyTypes) {
        ProvX509KeyManager.PublicKeyFilter filter = new ProvX509KeyManager.DefaultPublicKeyFilter(algorithm, clazz, keyUsageBit);
        String[] var6 = keyTypes;
        int var7 = keyTypes.length;

        for(int var8 = 0; var8 < var7; ++var8) {
            String keyType = var6[var8];
            addFilterToMap(filters, keyType, filter);
        }

    }

    private static void addFilterLegacyServer(Map<String, ProvX509KeyManager.PublicKeyFilter> filters, String algorithm, int... keyExchangeAlgorithms) {
        addFilterLegacyServer(filters, 0, algorithm, keyExchangeAlgorithms);
    }

    private static void addFilterLegacyServer(Map<String, ProvX509KeyManager.PublicKeyFilter> filters, int keyUsageBit, String algorithm, int... keyExchangeAlgorithms) {
        addFilterLegacyServer(filters, keyUsageBit, algorithm, (Class)null, keyExchangeAlgorithms);
    }

    private static void addFilterLegacyServer(Map<String, ProvX509KeyManager.PublicKeyFilter> filters, Class<? extends PublicKey> clazz, int... keyExchangeAlgorithms) {
        addFilterLegacyServer(filters, 0, (String)null, clazz, keyExchangeAlgorithms);
    }

    private static void addFilterLegacyServer(Map<String, ProvX509KeyManager.PublicKeyFilter> filters, int keyUsageBit, String algorithm, Class<? extends PublicKey> clazz, int... keyExchangeAlgorithms) {
        addFilter(filters, keyUsageBit, algorithm, clazz, getKeyTypesLegacyServer(keyExchangeAlgorithms));
    }

    private static void addFilterToMap(Map<String, ProvX509KeyManager.PublicKeyFilter> filters, String keyType, ProvX509KeyManager.PublicKeyFilter filter) {
        if (null != filters.put(keyType, filter)) {
            throw new IllegalStateException("Duplicate keys in filters");
        }
    }

    private static Map<String, ProvX509KeyManager.PublicKeyFilter> createFiltersClient() {
        Map<String, ProvX509KeyManager.PublicKeyFilter> filters = new HashMap();
        addFilter(filters, "Ed25519");
        addFilter(filters, "Ed448");
        addECFilter13(filters, 31);
        addECFilter13(filters, 32);
        addECFilter13(filters, 33);
        addECFilter13(filters, 23);
        addECFilter13(filters, 24);
        addECFilter13(filters, 25);
        addFilter(filters, "RSA");
        addFilter(filters, "RSASSA-PSS");
        addFilter(filters, DSAPublicKey.class, "DSA");
        addFilter(filters, ECPublicKey.class, "EC");
        return Collections.unmodifiableMap(filters);
    }

    private static Map<String, ProvX509KeyManager.PublicKeyFilter> createFiltersServer() {
        Map<String, ProvX509KeyManager.PublicKeyFilter> filters = new HashMap();
        addFilter(filters, "Ed25519");
        addFilter(filters, "Ed448");
        addECFilter13(filters, 31);
        addECFilter13(filters, 32);
        addECFilter13(filters, 33);
        addECFilter13(filters, 23);
        addECFilter13(filters, 24);
        addECFilter13(filters, 25);
        addFilter(filters, "RSA");
        addFilter(filters, "RSASSA-PSS");
        addFilterLegacyServer(filters, (Class)DSAPublicKey.class, 3, 22);
        addFilterLegacyServer(filters, (Class)ECPublicKey.class, 17);
        addFilterLegacyServer(filters, (String)"RSA", 5, 19, 23);
        addFilterLegacyServer(filters, 2, "RSA", 1);
        return Collections.unmodifiableMap(filters);
    }

    private static String[] getKeyTypesLegacyServer(int... keyExchangeAlgorithms) {
        int count = keyExchangeAlgorithms.length;
        String[] keyTypes = new String[count];

        for(int i = 0; i < count; ++i) {
            keyTypes[i] = JsseUtils.getKeyTypeLegacyServer(keyExchangeAlgorithms[i]);
        }

        return keyTypes;
    }

    ProvX509KeyManager(boolean isInFipsMode, JcaJceHelper helper, List<KeyStore.Builder> builders) {
        this.isInFipsMode = isInFipsMode;
        this.helper = helper;
        this.builders = builders;
    }

    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        return this.chooseAlias(getKeyTypes(keyTypes), issuers, TransportData.from(socket), false);
    }

    public BCX509Key chooseClientKeyBC(String[] keyTypes, Principal[] issuers, Socket socket) {
        return this.chooseKeyBC(getKeyTypes(keyTypes), issuers, TransportData.from(socket), false);
    }

    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return this.chooseAlias(getKeyTypes(keyTypes), issuers, TransportData.from(engine), false);
    }

    public BCX509Key chooseEngineClientKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return this.chooseKeyBC(getKeyTypes(keyTypes), issuers, TransportData.from(engine), false);
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return this.chooseAlias(getKeyTypes(keyType), issuers, TransportData.from(engine), true);
    }

    public BCX509Key chooseEngineServerKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return this.chooseKeyBC(getKeyTypes(keyTypes), issuers, TransportData.from(engine), true);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return this.chooseAlias(getKeyTypes(keyType), issuers, TransportData.from(socket), true);
    }

    public BCX509Key chooseServerKeyBC(String[] keyTypes, Principal[] issuers, Socket socket) {
        return this.chooseKeyBC(getKeyTypes(keyTypes), issuers, TransportData.from(socket), true);
    }

    public X509Certificate[] getCertificateChain(String alias) {
        KeyStore.PrivateKeyEntry entry = this.getPrivateKeyEntry(alias);
        return null == entry ? null : (X509Certificate[])((X509Certificate[])entry.getCertificateChain());
    }

    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return this.getAliases(getKeyTypes(keyType), issuers, (TransportData)null, false);
    }

    public PrivateKey getPrivateKey(String alias) {
        KeyStore.PrivateKeyEntry entry = this.getPrivateKeyEntry(alias);
        return null == entry ? null : entry.getPrivateKey();
    }

    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return this.getAliases(getKeyTypes(keyType), issuers, (TransportData)null, true);
    }

    public BCX509Key getKeyBC(String keyType, String alias) {
        KeyStore.PrivateKeyEntry entry = this.getPrivateKeyEntry(alias);
        if (null == entry) {
            return null;
        } else {
            PrivateKey privateKey = entry.getPrivateKey();
            if (null == privateKey) {
                return null;
            } else {
                X509Certificate[] certificateChain = JsseUtils.getX509CertificateChain(entry.getCertificateChain());
                return TlsUtils.isNullOrEmpty(certificateChain) ? null : new ProvX509Key(keyType, privateKey, certificateChain);
            }
        }
    }

    private String chooseAlias(List<String> keyTypes, Principal[] issuers, TransportData transportData, boolean forServer) {
        ProvX509KeyManager.Match bestMatch = this.getBestMatch(keyTypes, issuers, transportData, forServer);
        if (bestMatch.compareTo(ProvX509KeyManager.Match.NOTHING) < 0) {
            String keyType = (String)keyTypes.get(bestMatch.keyTypeIndex);
            String alias = getAlias(bestMatch, this.getNextVersionSuffix());
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine("Found matching key of type: " + keyType + ", returning alias: " + alias);
            }

            return alias;
        } else {
            LOG.fine("No matching key found");
            return null;
        }
    }

    private BCX509Key chooseKeyBC(List<String> keyTypes, Principal[] issuers, TransportData transportData, boolean forServer) {
        ProvX509KeyManager.Match bestMatch = this.getBestMatch(keyTypes, issuers, transportData, forServer);
        if (bestMatch.compareTo(ProvX509KeyManager.Match.NOTHING) < 0) {
            try {
                String keyType = (String)keyTypes.get(bestMatch.keyTypeIndex);
                BCX509Key keyBC = this.createKeyBC(keyType, bestMatch.builderIndex, bestMatch.localAlias, bestMatch.cachedKeyStore, bestMatch.cachedCertificateChain);
                if (null != keyBC) {
                    if (LOG.isLoggable(Level.FINE)) {
                        LOG.fine("Found matching key of type: " + keyType + ", from alias: " + bestMatch.builderIndex + "." + bestMatch.localAlias);
                    }

                    return keyBC;
                }
            } catch (Exception var8) {
                LOG.log(Level.FINER, "Failed to load private key", var8);
            }
        }

        LOG.fine("No matching key found");
        return null;
    }

    private BCX509Key createKeyBC(String keyType, int builderIndex, String localAlias, KeyStore keyStore, X509Certificate[] certificateChain) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore.Builder builder = (KeyStore.Builder)this.builders.get(builderIndex);
        KeyStore.ProtectionParameter protectionParameter = builder.getProtectionParameter(localAlias);
        Key key = KeyStoreUtil.getKey(keyStore, localAlias, protectionParameter);
        return key instanceof PrivateKey ? new ProvX509Key(keyType, (PrivateKey)key, certificateChain) : null;
    }

    private String[] getAliases(List<String> keyTypes, Principal[] issuers, TransportData transportData, boolean forServer) {
        if (!this.builders.isEmpty() && !keyTypes.isEmpty()) {
            int keyTypeLimit = keyTypes.size();
            Set<Principal> uniqueIssuers = getUniquePrincipals(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = getRequestedHostName(transportData, forServer);
            List<ProvX509KeyManager.Match> matches = null;
            int builderIndex = 0;

            for(int count = this.builders.size(); builderIndex < count; ++builderIndex) {
                try {
                    KeyStore.Builder builder = (KeyStore.Builder)this.builders.get(builderIndex);
                    KeyStore keyStore = builder.getKeyStore();
                    if (null != keyStore) {
                        Enumeration en = keyStore.aliases();

                        while(en.hasMoreElements()) {
                            String localAlias = (String)en.nextElement();
                            ProvX509KeyManager.Match match = this.getPotentialMatch(builderIndex, builder, keyStore, localAlias, keyTypes, keyTypeLimit, uniqueIssuers, algorithmConstraints, forServer, atDate, requestedHostName);
                            if (match.compareTo(ProvX509KeyManager.Match.NOTHING) < 0) {
                                matches = addToMatches(matches, match);
                            }
                        }
                    }
                } catch (KeyStoreException var18) {
                    LOG.log(Level.WARNING, "Failed to fully process KeyStore.Builder at index " + builderIndex, var18);
                }
            }

            if (null != matches && !matches.isEmpty()) {
                Collections.sort(matches);
                return getAliases(matches, this.getNextVersionSuffix());
            }
        }

        return null;
    }

    private ProvX509KeyManager.Match getBestMatch(List<String> keyTypes, Principal[] issuers, TransportData transportData, boolean forServer) {
        ProvX509KeyManager.Match bestMatchSoFar = ProvX509KeyManager.Match.NOTHING;
        if (!this.builders.isEmpty() && !keyTypes.isEmpty()) {
            int keyTypeLimit = keyTypes.size();
            Set<Principal> uniqueIssuers = getUniquePrincipals(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = getRequestedHostName(transportData, forServer);
            int builderIndex = 0;

            for(int count = this.builders.size(); builderIndex < count; ++builderIndex) {
                try {
                    KeyStore.Builder builder = (KeyStore.Builder)this.builders.get(builderIndex);
                    KeyStore keyStore = builder.getKeyStore();
                    if (null != keyStore) {
                        Enumeration en = keyStore.aliases();

                        while(en.hasMoreElements()) {
                            String localAlias = (String)en.nextElement();
                            ProvX509KeyManager.Match match = this.getPotentialMatch(builderIndex, builder, keyStore, localAlias, keyTypes, keyTypeLimit, uniqueIssuers, algorithmConstraints, forServer, atDate, requestedHostName);
                            if (match.compareTo(bestMatchSoFar) < 0) {
                                bestMatchSoFar = match;
                                if (match.isIdeal()) {
                                    return match;
                                }

                                if (match.isValid()) {
                                    keyTypeLimit = Math.min(keyTypeLimit, match.keyTypeIndex + 1);
                                }
                            }
                        }
                    }
                } catch (KeyStoreException var18) {
                    LOG.log(Level.WARNING, "Failed to fully process KeyStore.Builder at index " + builderIndex, var18);
                }
            }
        }

        return bestMatchSoFar;
    }

    private String getNextVersionSuffix() {
        return "." + this.versions.incrementAndGet();
    }

    private ProvX509KeyManager.Match getPotentialMatch(int builderIndex, KeyStore.Builder builder, KeyStore keyStore, String localAlias, List<String> keyTypes, int keyTypeLimit, Set<Principal> uniqueIssuers, BCAlgorithmConstraints algorithmConstraints, boolean forServer, Date atDate, String requestedHostName) throws KeyStoreException {
        if (keyStore.isKeyEntry(localAlias)) {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(keyStore.getCertificateChain(localAlias));
            int keyTypeIndex = getPotentialKeyType(keyTypes, keyTypeLimit, uniqueIssuers, algorithmConstraints, forServer, chain);
            if (keyTypeIndex >= 0) {
                ProvX509KeyManager.MatchQuality quality = getKeyTypeQuality(this.isInFipsMode, this.helper, keyTypes, algorithmConstraints, forServer, atDate, requestedHostName, chain, keyTypeIndex);
                if (ProvX509KeyManager.MatchQuality.NONE != quality) {
                    return new ProvX509KeyManager.Match(quality, keyTypeIndex, builderIndex, localAlias, keyStore, chain);
                }
            }
        }

        return ProvX509KeyManager.Match.NOTHING;
    }

    private KeyStore.PrivateKeyEntry getPrivateKeyEntry(String alias) {
        if (null == alias) {
            return null;
        } else {
            SoftReference<KeyStore.PrivateKeyEntry> entryRef = (SoftReference)this.cachedEntries.get(alias);
            KeyStore.PrivateKeyEntry result;
            if (null != entryRef) {
                result = (KeyStore.PrivateKeyEntry)entryRef.get();
                if (null != result) {
                    return result;
                }
            }

            result = this.loadPrivateKeyEntry(alias);
            if (null != result) {
                this.cachedEntries.put(alias, new SoftReference(result));
            }

            return result;
        }
    }

    private KeyStore.PrivateKeyEntry loadPrivateKeyEntry(String alias) {
        try {
            int builderIndexStart = 0;
            int builderIndexEnd = alias.indexOf(46, builderIndexStart);
            if (builderIndexEnd > builderIndexStart) {
                int localAliasStart = builderIndexEnd + 1;
                int localAliasEnd = alias.lastIndexOf(46);
                if (localAliasEnd > localAliasStart) {
                    int builderIndex = Integer.parseInt(alias.substring(builderIndexStart, builderIndexEnd));
                    if (0 <= builderIndex && builderIndex < this.builders.size()) {
                        KeyStore.Builder builder = (KeyStore.Builder)this.builders.get(builderIndex);
                        String localAlias = alias.substring(localAliasStart, localAliasEnd);
                        KeyStore keyStore = builder.getKeyStore();
                        if (null != keyStore) {
                            KeyStore.ProtectionParameter protectionParameter = builder.getProtectionParameter(localAlias);
                            java.security.KeyStore.Entry entry = keyStore.getEntry(localAlias, protectionParameter);
                            if (entry instanceof KeyStore.PrivateKeyEntry) {
                                return (KeyStore.PrivateKeyEntry)entry;
                            }
                        }
                    }
                }
            }
        } catch (Exception var12) {
            LOG.log(Level.FINER, "Failed to load PrivateKeyEntry: " + alias, var12);
        }

        return null;
    }

    static ProvX509KeyManager.MatchQuality getKeyTypeQuality(boolean isInFipsMode, JcaJceHelper helper, List<String> keyTypes, BCAlgorithmConstraints algorithmConstraints, boolean forServer, Date atDate, String requestedHostName, X509Certificate[] chain, int keyTypeIndex) {
        String keyType = (String)keyTypes.get(keyTypeIndex);
        LOG.finer("EE cert potentially usable for key type: " + keyType);
        if (!isSuitableChain(isInFipsMode, helper, chain, algorithmConstraints, forServer)) {
            LOG.finer("Unsuitable chain for key type: " + keyType);
            return ProvX509KeyManager.MatchQuality.NONE;
        } else {
            return getCertificateQuality(chain[0], atDate, requestedHostName);
        }
    }

    static List<String> getKeyTypes(String... keyTypes) {
        if (null != keyTypes && keyTypes.length > 0) {
            ArrayList<String> result = new ArrayList(keyTypes.length);
            String[] var2 = keyTypes;
            int var3 = keyTypes.length;

            for(int var4 = 0; var4 < var3; ++var4) {
                String keyType = var2[var4];
                if (null == keyType) {
                    throw new IllegalArgumentException("Key types cannot be null");
                }

                if (!result.contains(keyType)) {
                    result.add(keyType);
                }
            }

            return Collections.unmodifiableList(result);
        } else {
            return Collections.emptyList();
        }
    }

    static int getPotentialKeyType(List<String> keyTypes, int keyTypeLimit, Set<Principal> uniqueIssuers, BCAlgorithmConstraints algorithmConstraints, boolean forServer, X509Certificate[] chain) {
        return !isSuitableChainForIssuers(chain, uniqueIssuers) ? -1 : getSuitableKeyTypeForEECert(chain[0], keyTypes, keyTypeLimit, algorithmConstraints, forServer);
    }

    static String getRequestedHostName(TransportData transportData, boolean forServer) {
        if (null != transportData && forServer) {
            BCExtendedSSLSession sslSession = transportData.getHandshakeSession();
            if (null != sslSession) {
                BCSNIHostName sniHostName = JsseUtils.getSNIHostName(sslSession.getRequestedServerNames());
                if (null != sniHostName) {
                    return sniHostName.getAsciiName();
                }
            }
        }

        return null;
    }

    static Set<Principal> getUniquePrincipals(Principal[] principals) {
        if (null == principals) {
            return null;
        } else {
            if (principals.length > 0) {
                Set<Principal> result = new HashSet();

                for(int i = 0; i < principals.length; ++i) {
                    Principal principal = principals[i];
                    if (null != principal) {
                        result.add(principal);
                    }
                }

                if (!result.isEmpty()) {
                    return Collections.unmodifiableSet(result);
                }
            }

            return Collections.emptySet();
        }
    }

    static boolean isSuitableKeyType(boolean forServer, String keyType, X509Certificate eeCert, TransportData transportData) {
        Map<String, ProvX509KeyManager.PublicKeyFilter> filters = forServer ? FILTERS_SERVER : FILTERS_CLIENT;
        ProvX509KeyManager.PublicKeyFilter filter = (ProvX509KeyManager.PublicKeyFilter)filters.get(keyType);
        if (null == filter) {
            return false;
        } else {
            PublicKey publicKey = eeCert.getPublicKey();
            boolean[] keyUsage = eeCert.getKeyUsage();
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            return filter.accepts(publicKey, keyUsage, algorithmConstraints);
        }
    }

    private static List<ProvX509KeyManager.Match> addToMatches(List<ProvX509KeyManager.Match> matches, ProvX509KeyManager.Match match) {
        if (null == matches) {
            matches = new ArrayList();
        }

        ((List)matches).add(match);
        return (List)matches;
    }

    private static String getAlias(ProvX509KeyManager.Match match, String versionSuffix) {
        return match.builderIndex + "." + match.localAlias + versionSuffix;
    }

    private static String[] getAliases(List<ProvX509KeyManager.Match> matches, String versionSuffix) {
        int count = matches.size();
        int pos = 0;
        String[] result = new String[count];

        ProvX509KeyManager.Match match;
        for(Iterator var5 = matches.iterator(); var5.hasNext(); result[pos++] = getAlias(match, versionSuffix)) {
            match = (ProvX509KeyManager.Match)var5.next();
        }

        return result;
    }

    private static ProvX509KeyManager.MatchQuality getCertificateQuality(X509Certificate certificate, Date atDate, String requestedHostName) {
        try {
            certificate.checkValidity(atDate);
        } catch (CertificateException var5) {
            return ProvX509KeyManager.MatchQuality.EXPIRED;
        }

        if (null != requestedHostName) {
            try {
                ProvX509TrustManager.checkEndpointID(requestedHostName, certificate, "HTTPS");
            } catch (CertificateException var4) {
                return ProvX509KeyManager.MatchQuality.MISMATCH_SNI;
            }
        }

        if ("RSA".equalsIgnoreCase(JsseUtils.getPublicKeyAlgorithm(certificate.getPublicKey()))) {
            boolean[] keyUsage = certificate.getKeyUsage();
            if (ProvAlgorithmChecker.supportsKeyUsage(keyUsage, 0) && ProvAlgorithmChecker.supportsKeyUsage(keyUsage, 2)) {
                return ProvX509KeyManager.MatchQuality.RSA_MULTI_USE;
            }
        }

        return ProvX509KeyManager.MatchQuality.OK;
    }

    private static KeyPurposeId getRequiredExtendedKeyUsage(boolean forServer) {
        return !provKeyManagerCheckEKU ? null : (forServer ? KeyPurposeId.id_kp_serverAuth : KeyPurposeId.id_kp_clientAuth);
    }

    private static int getSuitableKeyTypeForEECert(X509Certificate eeCert, List<String> keyTypes, int keyTypeLimit, BCAlgorithmConstraints algorithmConstraints, boolean forServer) {
        Map<String, ProvX509KeyManager.PublicKeyFilter> filters = forServer ? FILTERS_SERVER : FILTERS_CLIENT;
        PublicKey publicKey = eeCert.getPublicKey();
        boolean[] keyUsage = eeCert.getKeyUsage();

        for(int keyTypeIndex = 0; keyTypeIndex < keyTypeLimit; ++keyTypeIndex) {
            String keyType = (String)keyTypes.get(keyTypeIndex);
            ProvX509KeyManager.PublicKeyFilter filter = (ProvX509KeyManager.PublicKeyFilter)filters.get(keyType);
            if (null != filter && filter.accepts(publicKey, keyUsage, algorithmConstraints)) {
                return keyTypeIndex;
            }
        }

        return -1;
    }

    private static boolean isSuitableChain(boolean isInFipsMode, JcaJceHelper helper, X509Certificate[] chain, BCAlgorithmConstraints algorithmConstraints, boolean forServer) {
        try {
            Set<X509Certificate> trustedCerts = Collections.emptySet();
            KeyPurposeId ekuOID = getRequiredExtendedKeyUsage(forServer);
            int kuBit = -1;
            ProvAlgorithmChecker.checkChain(isInFipsMode, helper, algorithmConstraints, trustedCerts, chain, ekuOID, kuBit);
            return true;
        } catch (CertPathValidatorException var8) {
            LOG.log(Level.FINEST, "Certificate chain check failed", var8);
            return false;
        }
    }

    private static boolean isSuitableChainForIssuers(X509Certificate[] chain, Set<Principal> uniqueIssuers) {
        if (TlsUtils.isNullOrEmpty(chain)) {
            return false;
        } else if (null != uniqueIssuers && !uniqueIssuers.isEmpty()) {
            int pos = chain.length;

            do {
                --pos;
                if (pos < 0) {
                    X509Certificate eeCert = chain[0];
                    return eeCert.getBasicConstraints() >= 0 && uniqueIssuers.contains(eeCert.getSubjectX500Principal());
                }
            } while(!uniqueIssuers.contains(chain[pos].getIssuerX500Principal()));

            return true;
        } else {
            return true;
        }
    }

    private static final class ECPublicKeyFilter13 implements ProvX509KeyManager.PublicKeyFilter {
        final ASN1ObjectIdentifier standardOID;

        ECPublicKeyFilter13(ASN1ObjectIdentifier standardOID) {
            this.standardOID = standardOID;
        }

        public boolean accepts(PublicKey publicKey, boolean[] keyUsage, BCAlgorithmConstraints algorithmConstraints) {
            return this.appliesTo(publicKey) && ProvAlgorithmChecker.permitsKeyUsage(publicKey, keyUsage, 0, algorithmConstraints);
        }

        private boolean appliesTo(PublicKey publicKey) {
            if ("EC".equalsIgnoreCase(JsseUtils.getPublicKeyAlgorithm(publicKey)) || ECPublicKey.class.isInstance(publicKey)) {
                ASN1ObjectIdentifier oid = JsseUtils.getNamedCurveOID(publicKey);
                if (this.standardOID.equals(oid)) {
                    return true;
                }
            }

            return false;
        }
    }

    private static final class DefaultPublicKeyFilter implements ProvX509KeyManager.PublicKeyFilter {
        final String algorithm;
        final Class<? extends PublicKey> clazz;
        final int keyUsageBit;

        DefaultPublicKeyFilter(String algorithm, Class<? extends PublicKey> clazz, int keyUsageBit) {
            this.algorithm = algorithm;
            this.clazz = clazz;
            this.keyUsageBit = keyUsageBit;
        }

        public boolean accepts(PublicKey publicKey, boolean[] keyUsage, BCAlgorithmConstraints algorithmConstraints) {
            return this.appliesTo(publicKey) && ProvAlgorithmChecker.permitsKeyUsage(publicKey, keyUsage, this.keyUsageBit, algorithmConstraints);
        }

        private boolean appliesTo(PublicKey publicKey) {
            return null != this.algorithm && this.algorithm.equalsIgnoreCase(JsseUtils.getPublicKeyAlgorithm(publicKey)) || null != this.clazz && this.clazz.isInstance(publicKey);
        }
    }

    interface PublicKeyFilter {
        boolean accepts(PublicKey var1, boolean[] var2, BCAlgorithmConstraints var3);
    }

    private static final class Match implements Comparable<ProvX509KeyManager.Match> {
        static final ProvX509KeyManager.MatchQuality INVALID;
        static final ProvX509KeyManager.Match NOTHING;
        final ProvX509KeyManager.MatchQuality quality;
        final int keyTypeIndex;
        final int builderIndex;
        final String localAlias;
        final KeyStore cachedKeyStore;
        final X509Certificate[] cachedCertificateChain;

        Match(ProvX509KeyManager.MatchQuality quality, int keyTypeIndex, int builderIndex, String localAlias, KeyStore cachedKeyStore, X509Certificate[] cachedCertificateChain) {
            this.quality = quality;
            this.keyTypeIndex = keyTypeIndex;
            this.builderIndex = builderIndex;
            this.localAlias = localAlias;
            this.cachedKeyStore = cachedKeyStore;
            this.cachedCertificateChain = cachedCertificateChain;
        }

        public int compareTo(ProvX509KeyManager.Match that) {
            boolean thisValid = this.isValid();
            boolean thatValid = that.isValid();
            if (thisValid != thatValid) {
                return thisValid ? -1 : 1;
            } else if (this.keyTypeIndex != that.keyTypeIndex) {
                return this.keyTypeIndex < that.keyTypeIndex ? -1 : 1;
            } else {
                return this.quality.compareTo(that.quality);
            }
        }

        boolean isIdeal() {
            return ProvX509KeyManager.MatchQuality.OK == this.quality && 0 == this.keyTypeIndex;
        }

        boolean isValid() {
            return this.quality.compareTo(INVALID) < 0;
        }

        static {
            INVALID = ProvX509KeyManager.MatchQuality.MISMATCH_SNI;
            NOTHING = new ProvX509KeyManager.Match(ProvX509KeyManager.MatchQuality.NONE, 2147483647, -1, (String)null, (KeyStore)null, (X509Certificate[])null);
        }
    }

    static enum MatchQuality {
        OK,
        RSA_MULTI_USE,
        MISMATCH_SNI,
        EXPIRED,
        NONE;

        private MatchQuality() {
        }
    }
}