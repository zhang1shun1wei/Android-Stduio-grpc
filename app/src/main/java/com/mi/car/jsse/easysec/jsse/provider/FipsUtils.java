package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.tls.NamedGroup;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/* access modifiers changed from: package-private */
public abstract class FipsUtils {
    private static final Set<String> FIPS_SUPPORTED_CIPHERSUITES = createFipsSupportedCipherSuites();
    private static final Set<String> FIPS_SUPPORTED_PROTOCOLS = createFipsSupportedProtocols();
    private static final boolean provAllowGCMCiphers = false;
    private static final boolean provAllowRSAKeyExchange = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.fips.allowRSAKeyExchange", true);

    FipsUtils() {
    }

    private static Set<String> createFipsSupportedCipherSuites() {
        Set<String> cs = new HashSet<>();
        cs.add("TLS_AES_128_CCM_8_SHA256");
        cs.add("TLS_AES_128_CCM_SHA256");
        cs.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
        cs.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA");
        cs.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");
        cs.add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_DHE_RSA_WITH_AES_128_CCM");
        cs.add("TLS_DHE_RSA_WITH_AES_128_CCM_8");
        cs.add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
        cs.add("TLS_DHE_RSA_WITH_AES_256_CCM");
        cs.add("TLS_DHE_RSA_WITH_AES_256_CCM_8");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CCM");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CCM");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
        if (provAllowRSAKeyExchange) {
            cs.add("TLS_RSA_WITH_AES_128_CBC_SHA");
            cs.add("TLS_RSA_WITH_AES_128_CBC_SHA256");
            cs.add("TLS_RSA_WITH_AES_128_CCM");
            cs.add("TLS_RSA_WITH_AES_128_CCM_8");
            cs.add("TLS_RSA_WITH_AES_256_CBC_SHA");
            cs.add("TLS_RSA_WITH_AES_256_CBC_SHA256");
            cs.add("TLS_RSA_WITH_AES_256_CCM");
            cs.add("TLS_RSA_WITH_AES_256_CCM_8");
        }
        return Collections.unmodifiableSet(cs);
    }

    private static Set<String> createFipsSupportedProtocols() {
        Set<String> ps = new HashSet<>();
        ps.add("TLSv1");
        ps.add("TLSv1.1");
        ps.add("TLSv1.2");
        ps.add("TLSv1.3");
        return Collections.unmodifiableSet(ps);
    }

    static boolean isFipsCipherSuite(String cipherSuite) {
        return cipherSuite != null && FIPS_SUPPORTED_CIPHERSUITES.contains(cipherSuite);
    }

    static boolean isFipsNamedGroup(int namedGroup) {
        switch (namedGroup) {
            case 23:
            case 24:
            case 25:
            case NamedGroup.ffdhe2048 /*{ENCODED_INT: 256}*/:
            case NamedGroup.ffdhe3072 /*{ENCODED_INT: 257}*/:
            case NamedGroup.ffdhe4096 /*{ENCODED_INT: 258}*/:
            case NamedGroup.ffdhe6144 /*{ENCODED_INT: 259}*/:
            case NamedGroup.ffdhe8192 /*{ENCODED_INT: 260}*/:
                return true;
            default:
                return false;
        }
    }

    static boolean isFipsProtocol(String protocol) {
        return protocol != null && FIPS_SUPPORTED_PROTOCOLS.contains(protocol);
    }

    static boolean isFipsSignatureScheme(int signatureScheme) {
        switch (signatureScheme) {
            case SignatureScheme.rsa_pkcs1_sha1 /*{ENCODED_INT: 513}*/:
            case 514:
            case SignatureScheme.ecdsa_sha1 /*{ENCODED_INT: 515}*/:
            case 769:
            case 770:
            case 771:
            case SignatureScheme.rsa_pkcs1_sha256 /*{ENCODED_INT: 1025}*/:
            case 1026:
            case SignatureScheme.ecdsa_secp256r1_sha256 /*{ENCODED_INT: 1027}*/:
            case SignatureScheme.rsa_pkcs1_sha384 /*{ENCODED_INT: 1281}*/:
            case SignatureScheme.ecdsa_secp384r1_sha384 /*{ENCODED_INT: 1283}*/:
            case SignatureScheme.rsa_pkcs1_sha512 /*{ENCODED_INT: 1537}*/:
            case SignatureScheme.ecdsa_secp521r1_sha512 /*{ENCODED_INT: 1539}*/:
            case SignatureScheme.rsa_pss_rsae_sha256 /*{ENCODED_INT: 2052}*/:
            case SignatureScheme.rsa_pss_rsae_sha384 /*{ENCODED_INT: 2053}*/:
            case SignatureScheme.rsa_pss_rsae_sha512 /*{ENCODED_INT: 2054}*/:
            case SignatureScheme.rsa_pss_pss_sha256 /*{ENCODED_INT: 2057}*/:
            case SignatureScheme.rsa_pss_pss_sha384 /*{ENCODED_INT: 2058}*/:
            case SignatureScheme.rsa_pss_pss_sha512 /*{ENCODED_INT: 2059}*/:
                return true;
            default:
                return false;
        }
    }

    static void removeNonFipsCipherSuites(Collection<String> cipherSuites) {
        cipherSuites.retainAll(FIPS_SUPPORTED_CIPHERSUITES);
    }

    static void removeNonFipsProtocols(Collection<String> protocols) {
        protocols.retainAll(FIPS_SUPPORTED_PROTOCOLS);
    }
}
