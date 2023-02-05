package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.jsse.java.security.BCCryptoPrimitive;
import com.mi.car.jsse.easysec.jsse.provider.NamedGroupInfo;
import com.mi.car.jsse.easysec.tls.NamedGroup;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JcaTlsCrypto;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Integers;
import java.security.AlgorithmParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Vector;
import java.util.logging.Logger;

/* access modifiers changed from: package-private */
public class SignatureSchemeInfo {
    private static final int[] CANDIDATES_DEFAULT = createCandidatesDefault();
    private static final Logger LOG = Logger.getLogger(SignatureSchemeInfo.class.getName());
    private static final String PROPERTY_CLIENT_SIGNATURE_SCHEMES = "jdk.tls.client.SignatureSchemes";
    private static final String PROPERTY_SERVER_SIGNATURE_SCHEMES = "jdk.tls.server.SignatureSchemes";
    static final int historical_dsa_sha1 = 514;
    static final int historical_dsa_sha224 = 770;
    static final int historical_dsa_sha256 = 1026;
    static final int historical_ecdsa_sha224 = 771;
    static final int historical_rsa_md5 = 257;
    static final int historical_rsa_sha224 = 769;
    private final AlgorithmParameters algorithmParameters;
    private final All all;
    private final boolean disabled13;
    private final boolean enabled;
    private final NamedGroupInfo namedGroupInfo;

    /* access modifiers changed from: private */
    public enum All {
        ed25519(SignatureScheme.ed25519, "Ed25519", "Ed25519"),
        ed448(SignatureScheme.ed448, "Ed448", "Ed448"),
        ecdsa_secp256r1_sha256(SignatureScheme.ecdsa_secp256r1_sha256, "SHA256withECDSA", "EC"),
        ecdsa_secp384r1_sha384(SignatureScheme.ecdsa_secp384r1_sha384, "SHA384withECDSA", "EC"),
        ecdsa_secp521r1_sha512(SignatureScheme.ecdsa_secp521r1_sha512, "SHA512withECDSA", "EC"),
        ecdsa_brainpoolP256r1tls13_sha256(SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256, "SHA256withECDSA", "EC"),
        ecdsa_brainpoolP384r1tls13_sha384(SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384, "SHA384withECDSA", "EC"),
        ecdsa_brainpoolP512r1tls13_sha512(SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512, "SHA512withECDSA", "EC"),
        rsa_pss_pss_sha256(SignatureScheme.rsa_pss_pss_sha256, "SHA256withRSAandMGF1", "RSASSA-PSS"),
        rsa_pss_pss_sha384(SignatureScheme.rsa_pss_pss_sha384, "SHA384withRSAandMGF1", "RSASSA-PSS"),
        rsa_pss_pss_sha512(SignatureScheme.rsa_pss_pss_sha512, "SHA512withRSAandMGF1", "RSASSA-PSS"),
        rsa_pss_rsae_sha256(SignatureScheme.rsa_pss_rsae_sha256, "SHA256withRSAandMGF1", "RSA"),
        rsa_pss_rsae_sha384(SignatureScheme.rsa_pss_rsae_sha384, "SHA384withRSAandMGF1", "RSA"),
        rsa_pss_rsae_sha512(SignatureScheme.rsa_pss_rsae_sha512, "SHA512withRSAandMGF1", "RSA"),
        rsa_pkcs1_sha256((int) SignatureScheme.rsa_pkcs1_sha256, "SHA256withRSA", "RSA", true),
        rsa_pkcs1_sha384((int) SignatureScheme.rsa_pkcs1_sha384, "SHA384withRSA", "RSA", true),
        rsa_pkcs1_sha512((int) SignatureScheme.rsa_pkcs1_sha512, "SHA512withRSA", "RSA", true),
        sm2sig_sm3(SignatureScheme.sm2sig_sm3, "SM3withSM2", "EC"),
        dsa_sha256((int) SignatureSchemeInfo.historical_dsa_sha256, "dsa_sha256", "SHA256withDSA", "DSA"),
        ecdsa_sha224((int) SignatureSchemeInfo.historical_ecdsa_sha224, "ecdsa_sha224", "SHA224withECDSA", "EC"),
        rsa_sha224((int) SignatureSchemeInfo.historical_rsa_sha224, "rsa_sha224", "SHA224withRSA", "RSA"),
        dsa_sha224((int) SignatureSchemeInfo.historical_dsa_sha224, "dsa_sha224", "SHA224withDSA", "DSA"),
        ecdsa_sha1((int) SignatureScheme.ecdsa_sha1, "SHA1withECDSA", "EC", true),
        rsa_pkcs1_sha1((int) SignatureScheme.rsa_pkcs1_sha1, "SHA1withRSA", "RSA", true),
        dsa_sha1((int) SignatureSchemeInfo.historical_dsa_sha1, "dsa_sha1", "SHA1withDSA", "DSA"),
        rsa_md5(257, "rsa_md5", "MD5withRSA", "RSA");
        
        private final String jcaSignatureAlgorithm;
        private final String jcaSignatureAlgorithmBC;
        private final String keyAlgorithm;
        private final String keyType13;
        private final String name;
        private final int namedGroup13;
        private final int signatureScheme;
        private final boolean supportedCerts13;
        private final boolean supportedPost13;
        private final boolean supportedPre13;
        private final String text;

        private All(int signatureScheme2, String jcaSignatureAlgorithm2, String keyAlgorithm2) {
            this(signatureScheme2, jcaSignatureAlgorithm2, keyAlgorithm2, true, true, SignatureScheme.getNamedGroup(signatureScheme2));
        }

        private All(int signatureScheme2, String jcaSignatureAlgorithm2, String keyAlgorithm2, boolean supportedCerts132) {
            this(signatureScheme2, jcaSignatureAlgorithm2, keyAlgorithm2, false, supportedCerts132, -1);
        }

        private All(int signatureScheme2, String jcaSignatureAlgorithm2, String keyAlgorithm2, boolean supportedPost132, boolean supportedCerts132, int namedGroup132) {
            this(signatureScheme2, SignatureScheme.getName(signatureScheme2), jcaSignatureAlgorithm2, keyAlgorithm2, supportedPost132, supportedCerts132, namedGroup132);
        }

        private All(int signatureScheme2, String name2, String jcaSignatureAlgorithm2, String keyAlgorithm2) {
            this(signatureScheme2, name2, jcaSignatureAlgorithm2, keyAlgorithm2, false, false, -1);
        }

        private All(int signatureScheme2, String name2, String jcaSignatureAlgorithm2, String keyAlgorithm2, boolean supportedPost132, boolean supportedCerts132, int namedGroup132) {
            String keyType132 = JsseUtils.getKeyType13(keyAlgorithm2, namedGroup132);
            String jcaSignatureAlgorithmBC2 = JsseUtils.getJcaSignatureAlgorithmBC(jcaSignatureAlgorithm2, keyAlgorithm2);
            this.signatureScheme = signatureScheme2;
            this.name = name2;
            this.text = name2 + "(0x" + Integer.toHexString(signatureScheme2) + ")";
            this.jcaSignatureAlgorithm = jcaSignatureAlgorithm2;
            this.jcaSignatureAlgorithmBC = jcaSignatureAlgorithmBC2;
            this.keyAlgorithm = keyAlgorithm2;
            this.keyType13 = keyType132;
            this.supportedPost13 = supportedPost132;
            this.supportedPre13 = namedGroup132 < 0 || NamedGroup.canBeNegotiated(namedGroup132, ProtocolVersion.TLSv12);
            this.supportedCerts13 = supportedCerts132;
            this.namedGroup13 = namedGroup132;
        }
    }

    static class PerContext {
        private final int[] candidatesClient;
        private final int[] candidatesServer;
        private final Map<Integer, SignatureSchemeInfo> index;

        PerContext(Map<Integer, SignatureSchemeInfo> index2, int[] candidatesClient2, int[] candidatesServer2) {
            this.index = index2;
            this.candidatesClient = candidatesClient2;
            this.candidatesServer = candidatesServer2;
        }
    }

    static PerContext createPerContext(boolean isFipsContext, JcaTlsCrypto crypto, NamedGroupInfo.PerContext namedGroups) {
        Map<Integer, SignatureSchemeInfo> index = createIndex(isFipsContext, crypto, namedGroups);
        return new PerContext(index, createCandidates(index, PROPERTY_CLIENT_SIGNATURE_SCHEMES), createCandidates(index, PROPERTY_SERVER_SIGNATURE_SCHEMES));
    }

    static List<SignatureSchemeInfo> getActiveCertsSignatureSchemes(PerContext perContext, boolean isServer, ProvSSLParameters sslParameters, ProtocolVersion[] activeProtocolVersions, NamedGroupInfo.PerConnection namedGroups) {
        ProtocolVersion latest = ProtocolVersion.getLatestTLS(activeProtocolVersions);
        if (!TlsUtils.isSignatureAlgorithmsExtensionAllowed(latest)) {
            return null;
        }
        int[] candidates = isServer ? perContext.candidatesServer : perContext.candidatesClient;
        ProtocolVersion earliest = ProtocolVersion.getEarliestTLS(activeProtocolVersions);
        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();
        boolean post13Active = TlsUtils.isTLSv13(latest);
        boolean pre13Active = !TlsUtils.isTLSv13(earliest);
        int count = candidates.length;
        ArrayList<SignatureSchemeInfo> result = new ArrayList<>(count);
        for (int i : candidates) {
            SignatureSchemeInfo signatureSchemeInfo = (SignatureSchemeInfo) perContext.index.get(Integers.valueOf(i));
            if (signatureSchemeInfo != null && signatureSchemeInfo.isActiveCerts(algorithmConstraints, post13Active, pre13Active, namedGroups)) {
                result.add(signatureSchemeInfo);
            }
        }
        if (result.isEmpty()) {
            return Collections.emptyList();
        }
        result.trimToSize();
        return Collections.unmodifiableList(result);
    }

    static String[] getJcaSignatureAlgorithms(Collection<SignatureSchemeInfo> infos) {
        if (infos == null) {
            return TlsUtils.EMPTY_STRINGS;
        }
        ArrayList<String> result = new ArrayList<>();
        for (SignatureSchemeInfo info : infos) {
            result.add(info.getJcaSignatureAlgorithm());
        }
        return (String[]) result.toArray(TlsUtils.EMPTY_STRINGS);
    }

    static String[] getJcaSignatureAlgorithmsBC(Collection<SignatureSchemeInfo> infos) {
        if (infos == null) {
            return TlsUtils.EMPTY_STRINGS;
        }
        ArrayList<String> result = new ArrayList<>();
        for (SignatureSchemeInfo info : infos) {
            result.add(info.getJcaSignatureAlgorithmBC());
        }
        return (String[]) result.toArray(TlsUtils.EMPTY_STRINGS);
    }

    static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(int signatureScheme) {
        if (TlsUtils.isValidUint16(signatureScheme)) {
            return SignatureScheme.getSignatureAndHashAlgorithm(signatureScheme);
        }
        throw new IllegalArgumentException();
    }

    static Vector<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithms(List<SignatureSchemeInfo> signatureSchemeInfos) {
        if (signatureSchemeInfos == null || signatureSchemeInfos.isEmpty()) {
            return null;
        }
        Vector<SignatureAndHashAlgorithm> result = new Vector<>(signatureSchemeInfos.size());
        for (SignatureSchemeInfo signatureSchemeInfo : signatureSchemeInfos) {
            if (signatureSchemeInfo != null) {
                result.add(signatureSchemeInfo.getSignatureAndHashAlgorithm());
            }
        }
        if (result.isEmpty()) {
            return null;
        }
        result.trimToSize();
        return result;
    }

    static List<SignatureSchemeInfo> getSignatureSchemes(PerContext perContext, Vector<SignatureAndHashAlgorithm> sigAndHashAlgs) {
        if (sigAndHashAlgs == null || sigAndHashAlgs.isEmpty()) {
            return null;
        }
        int count = sigAndHashAlgs.size();
        ArrayList<SignatureSchemeInfo> result = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            SignatureAndHashAlgorithm sigAndHashAlg = sigAndHashAlgs.elementAt(i);
            if (sigAndHashAlg != null) {
                SignatureSchemeInfo signatureSchemeInfo = (SignatureSchemeInfo) perContext.index.get(Integer.valueOf(SignatureScheme.from(sigAndHashAlg)));
                if (signatureSchemeInfo != null) {
                    result.add(signatureSchemeInfo);
                }
            }
        }
        if (result.isEmpty()) {
            return null;
        }
        result.trimToSize();
        return Collections.unmodifiableList(result);
    }

    private static void addSignatureScheme(boolean isFipsContext, JcaTlsCrypto crypto, NamedGroupInfo.PerContext ng, Map<Integer, SignatureSchemeInfo> ss, All all2) {
        int signatureScheme = all2.signatureScheme;
        if (!isFipsContext || FipsUtils.isFipsSignatureScheme(signatureScheme)) {
            NamedGroupInfo namedGroupInfo2 = null;
            boolean disabled132 = false;
            int namedGroup13 = all2.namedGroup13;
            if (namedGroup13 >= 0 && ((namedGroupInfo2 = NamedGroupInfo.getNamedGroup(ng, namedGroup13)) == null || !namedGroupInfo2.isEnabled() || !namedGroupInfo2.isSupportedPost13())) {
                disabled132 = true;
            }
            boolean enabled2 = crypto.hasSignatureScheme(signatureScheme);
            AlgorithmParameters algorithmParameters2 = null;
            if (enabled2) {
                try {
                    algorithmParameters2 = crypto.getSignatureSchemeAlgorithmParameters(signatureScheme);
                } catch (Exception e) {
                    enabled2 = false;
                }
            }
            if (ss.put(Integer.valueOf(signatureScheme), new SignatureSchemeInfo(all2, algorithmParameters2, namedGroupInfo2, enabled2, disabled132)) != null) {
                throw new IllegalStateException("Duplicate entries for SignatureSchemeInfo");
            }
        }
    }

    private static int[] createCandidates(Map<Integer, SignatureSchemeInfo> index, String propertyName) {
        int count;
        String[] names = PropertyUtils.getStringArraySystemProperty(propertyName);
        if (names == null) {
            return CANDIDATES_DEFAULT;
        }
        int[] result = new int[names.length];
        int length = names.length;
        int i = 0;
        int count2 = 0;
        while (i < length) {
            String name = names[i];
            int signatureScheme = getSignatureSchemeByName(name);
            if (signatureScheme < 0) {
                LOG.warning("'" + propertyName + "' contains unrecognised SignatureScheme: " + name);
                count = count2;
            } else {
                SignatureSchemeInfo signatureSchemeInfo = index.get(Integer.valueOf(signatureScheme));
                if (signatureSchemeInfo == null) {
                    LOG.warning("'" + propertyName + "' contains unsupported SignatureScheme: " + name);
                    count = count2;
                } else if (!signatureSchemeInfo.isEnabled()) {
                    LOG.warning("'" + propertyName + "' contains disabled SignatureScheme: " + name);
                    count = count2;
                } else {
                    count = count2 + 1;
                    result[count2] = signatureScheme;
                }
            }
            i++;
            count2 = count;
        }
        if (count2 < result.length) {
            result = Arrays.copyOf(result, count2);
        }
        if (result.length >= 1) {
            return result;
        }
        LOG.severe("'" + propertyName + "' contained no usable SignatureScheme values");
        return result;
    }

    private static int[] createCandidatesDefault() {
        All[] values = All.values();
        int[] result = new int[values.length];
        for (int i = 0; i < values.length; i++) {
            result[i] = values[i].signatureScheme;
        }
        return result;
    }

    private static Map<Integer, SignatureSchemeInfo> createIndex(boolean isFipsContext, JcaTlsCrypto crypto, NamedGroupInfo.PerContext ng) {
        Map<Integer, SignatureSchemeInfo> ss = new TreeMap<>();
        for (All all2 : All.values()) {
            addSignatureScheme(isFipsContext, crypto, ng, ss, all2);
        }
        return ss;
    }

    private static int getSignatureSchemeByName(String name) {
        All[] values = All.values();
        for (All all2 : values) {
            if (all2.name.equalsIgnoreCase(name)) {
                return all2.signatureScheme;
            }
        }
        return -1;
    }

    private static boolean isECDSA(int signatureScheme) {
        switch (signatureScheme) {
            case SignatureScheme.ecdsa_sha1 /*{ENCODED_INT: 515}*/:
            case historical_ecdsa_sha224 /*{ENCODED_INT: 771}*/:
            case SignatureScheme.ecdsa_secp256r1_sha256 /*{ENCODED_INT: 1027}*/:
            case SignatureScheme.ecdsa_secp384r1_sha384 /*{ENCODED_INT: 1283}*/:
            case SignatureScheme.ecdsa_secp521r1_sha512 /*{ENCODED_INT: 1539}*/:
            case SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256 /*{ENCODED_INT: 2074}*/:
            case SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384 /*{ENCODED_INT: 2075}*/:
            case SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512 /*{ENCODED_INT: 2076}*/:
                return true;
            default:
                return false;
        }
    }

    SignatureSchemeInfo(All all2, AlgorithmParameters algorithmParameters2, NamedGroupInfo namedGroupInfo2, boolean enabled2, boolean disabled132) {
        this.all = all2;
        this.algorithmParameters = algorithmParameters2;
        this.namedGroupInfo = namedGroupInfo2;
        this.enabled = enabled2;
        this.disabled13 = disabled132;
    }

    /* access modifiers changed from: package-private */
    public short getHashAlgorithm() {
        return SignatureScheme.getHashAlgorithm(this.all.signatureScheme);
    }

    /* access modifiers changed from: package-private */
    public String getJcaSignatureAlgorithm() {
        return this.all.jcaSignatureAlgorithm;
    }

    /* access modifiers changed from: package-private */
    public String getJcaSignatureAlgorithmBC() {
        return this.all.jcaSignatureAlgorithmBC;
    }

    /* access modifiers changed from: package-private */
    public String getKeyType() {
        return this.all.keyAlgorithm;
    }

    /* access modifiers changed from: package-private */
    public String getKeyType13() {
        return this.all.keyType13;
    }

    /* access modifiers changed from: package-private */
    public String getName() {
        return this.all.name;
    }

    /* access modifiers changed from: package-private */
    public NamedGroupInfo getNamedGroupInfo() {
        return this.namedGroupInfo;
    }

    /* access modifiers changed from: package-private */
    public short getSignatureAlgorithm() {
        return SignatureScheme.getSignatureAlgorithm(this.all.signatureScheme);
    }

    /* access modifiers changed from: package-private */
    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
        return getSignatureAndHashAlgorithm(this.all.signatureScheme);
    }

    /* access modifiers changed from: package-private */
    public int getSignatureScheme() {
        return this.all.signatureScheme;
    }

    /* access modifiers changed from: package-private */
    public boolean isActive(BCAlgorithmConstraints algorithmConstraints, boolean post13Active, boolean pre13Active, NamedGroupInfo.PerConnection namedGroupInfos) {
        boolean z;
        if (this.enabled) {
            if (!post13Active || !isSupportedPost13()) {
                z = false;
            } else {
                z = true;
            }
            if (isNamedGroupOK(z, pre13Active && isSupportedPre13(), namedGroupInfos) && isPermittedBy(algorithmConstraints)) {
                return true;
            }
        }
        return false;
    }

    /* access modifiers changed from: package-private */
    public boolean isActiveCerts(BCAlgorithmConstraints algorithmConstraints, boolean post13Active, boolean pre13Active, NamedGroupInfo.PerConnection namedGroupInfos) {
        boolean z;
        if (this.enabled) {
            if (!post13Active || !isSupportedCerts13()) {
                z = false;
            } else {
                z = true;
            }
            if (isNamedGroupOK(z, pre13Active && isSupportedPre13(), namedGroupInfos) && isPermittedBy(algorithmConstraints)) {
                return true;
            }
        }
        return false;
    }

    /* access modifiers changed from: package-private */
    public boolean isEnabled() {
        return this.enabled;
    }

    /* access modifiers changed from: package-private */
    public boolean isSupportedPost13() {
        return !this.disabled13 && this.all.supportedPost13;
    }

    /* access modifiers changed from: package-private */
    public boolean isSupportedPre13() {
        return this.all.supportedPre13;
    }

    /* access modifiers changed from: package-private */
    public boolean isSupportedCerts13() {
        return !this.disabled13 && this.all.supportedCerts13;
    }

    public String toString() {
        return this.all.text;
    }

    private boolean isNamedGroupOK(boolean post13Allowed, boolean pre13Allowed, NamedGroupInfo.PerConnection namedGroupInfos) {
        if (this.namedGroupInfo == null) {
            return (post13Allowed || pre13Allowed) && (!isECDSA(this.all.signatureScheme) || NamedGroupInfo.hasAnyECDSALocal(namedGroupInfos));
        }
        if (!post13Allowed || !NamedGroupInfo.hasLocal(namedGroupInfos, this.namedGroupInfo.getNamedGroup())) {
            return pre13Allowed && NamedGroupInfo.hasAnyECDSALocal(namedGroupInfos);
        }
        return true;
    }

    private boolean isPermittedBy(BCAlgorithmConstraints algorithmConstraints) {
        Set<BCCryptoPrimitive> primitives = JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC;
        return algorithmConstraints.permits(primitives, this.all.name, null) && algorithmConstraints.permits(primitives, this.all.keyAlgorithm, null) && algorithmConstraints.permits(primitives, this.all.jcaSignatureAlgorithm, this.algorithmParameters);
    }
}
