package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;

public class SignatureScheme {
    public static final int ecdsa_brainpoolP256r1tls13_sha256 = 2074;
    public static final int ecdsa_brainpoolP384r1tls13_sha384 = 2075;
    public static final int ecdsa_brainpoolP512r1tls13_sha512 = 2076;
    public static final int ecdsa_secp256r1_sha256 = 1027;
    public static final int ecdsa_secp384r1_sha384 = 1283;
    public static final int ecdsa_secp521r1_sha512 = 1539;
    public static final int ecdsa_sha1 = 515;
    public static final int ed25519 = 2055;
    public static final int ed448 = 2056;
    public static final int rsa_pkcs1_sha1 = 513;
    public static final int rsa_pkcs1_sha256 = 1025;
    public static final int rsa_pkcs1_sha384 = 1281;
    public static final int rsa_pkcs1_sha512 = 1537;
    public static final int rsa_pss_pss_sha256 = 2057;
    public static final int rsa_pss_pss_sha384 = 2058;
    public static final int rsa_pss_pss_sha512 = 2059;
    public static final int rsa_pss_rsae_sha256 = 2052;
    public static final int rsa_pss_rsae_sha384 = 2053;
    public static final int rsa_pss_rsae_sha512 = 2054;
    public static final int sm2sig_sm3 = 1800;

    public static int from(SignatureAndHashAlgorithm sigAndHashAlg) {
        if (sigAndHashAlg != null) {
            return from(sigAndHashAlg.getHash(), sigAndHashAlg.getSignature());
        }
        throw new NullPointerException();
    }

    public static int from(short hashAlgorithm, short signatureAlgorithm) {
        return ((hashAlgorithm & 255) << 8) | (signatureAlgorithm & 255);
    }

    public static int getCryptoHashAlgorithm(int signatureScheme) {
        switch (signatureScheme) {
            case sm2sig_sm3 /*{ENCODED_INT: 1800}*/:
                return 7;
            case rsa_pss_rsae_sha256 /*{ENCODED_INT: 2052}*/:
            case rsa_pss_pss_sha256 /*{ENCODED_INT: 2057}*/:
            case ecdsa_brainpoolP256r1tls13_sha256 /*{ENCODED_INT: 2074}*/:
                return 4;
            case rsa_pss_rsae_sha384 /*{ENCODED_INT: 2053}*/:
            case rsa_pss_pss_sha384 /*{ENCODED_INT: 2058}*/:
            case ecdsa_brainpoolP384r1tls13_sha384 /*{ENCODED_INT: 2075}*/:
                return 5;
            case rsa_pss_rsae_sha512 /*{ENCODED_INT: 2054}*/:
            case rsa_pss_pss_sha512 /*{ENCODED_INT: 2059}*/:
            case ecdsa_brainpoolP512r1tls13_sha512 /*{ENCODED_INT: 2076}*/:
                return 6;
            case ed25519 /*{ENCODED_INT: 2055}*/:
            case ed448 /*{ENCODED_INT: 2056}*/:
                return -1;
            default:
                short hashAlgorithm = getHashAlgorithm(signatureScheme);
                if (8 == hashAlgorithm || !HashAlgorithm.isRecognized(hashAlgorithm)) {
                    return -1;
                }
                return TlsCryptoUtils.getHash(hashAlgorithm);
        }
    }

    public static String getName(int signatureScheme) {
        switch (signatureScheme) {
            case rsa_pkcs1_sha1 /*{ENCODED_INT: 513}*/:
                return "rsa_pkcs1_sha1";
            case ecdsa_sha1 /*{ENCODED_INT: 515}*/:
                return "ecdsa_sha1";
            case rsa_pkcs1_sha256 /*{ENCODED_INT: 1025}*/:
                return "rsa_pkcs1_sha256";
            case ecdsa_secp256r1_sha256 /*{ENCODED_INT: 1027}*/:
                return "ecdsa_secp256r1_sha256";
            case rsa_pkcs1_sha384 /*{ENCODED_INT: 1281}*/:
                return "rsa_pkcs1_sha384";
            case ecdsa_secp384r1_sha384 /*{ENCODED_INT: 1283}*/:
                return "ecdsa_secp384r1_sha384";
            case rsa_pkcs1_sha512 /*{ENCODED_INT: 1537}*/:
                return "rsa_pkcs1_sha512";
            case ecdsa_secp521r1_sha512 /*{ENCODED_INT: 1539}*/:
                return "ecdsa_secp521r1_sha512";
            case sm2sig_sm3 /*{ENCODED_INT: 1800}*/:
                return "sm2sig_sm3";
            case rsa_pss_rsae_sha256 /*{ENCODED_INT: 2052}*/:
                return "rsa_pss_rsae_sha256";
            case rsa_pss_rsae_sha384 /*{ENCODED_INT: 2053}*/:
                return "rsa_pss_rsae_sha384";
            case rsa_pss_rsae_sha512 /*{ENCODED_INT: 2054}*/:
                return "rsa_pss_rsae_sha512";
            case ed25519 /*{ENCODED_INT: 2055}*/:
                return "ed25519";
            case ed448 /*{ENCODED_INT: 2056}*/:
                return "ed448";
            case rsa_pss_pss_sha256 /*{ENCODED_INT: 2057}*/:
                return "rsa_pss_pss_sha256";
            case rsa_pss_pss_sha384 /*{ENCODED_INT: 2058}*/:
                return "rsa_pss_pss_sha384";
            case rsa_pss_pss_sha512 /*{ENCODED_INT: 2059}*/:
                return "rsa_pss_pss_sha512";
            case ecdsa_brainpoolP256r1tls13_sha256 /*{ENCODED_INT: 2074}*/:
                return "ecdsa_brainpoolP256r1tls13_sha256";
            case ecdsa_brainpoolP384r1tls13_sha384 /*{ENCODED_INT: 2075}*/:
                return "ecdsa_brainpoolP384r1tls13_sha384";
            case ecdsa_brainpoolP512r1tls13_sha512 /*{ENCODED_INT: 2076}*/:
                return "ecdsa_brainpoolP512r1tls13_sha512";
            default:
                return "UNKNOWN";
        }
    }

    public static int getNamedGroup(int signatureScheme) {
        switch (signatureScheme) {
            case ecdsa_secp256r1_sha256 /*{ENCODED_INT: 1027}*/:
                return 23;
            case ecdsa_secp384r1_sha384 /*{ENCODED_INT: 1283}*/:
                return 24;
            case ecdsa_secp521r1_sha512 /*{ENCODED_INT: 1539}*/:
                return 25;
            case sm2sig_sm3 /*{ENCODED_INT: 1800}*/:
                return 41;
            case ecdsa_brainpoolP256r1tls13_sha256 /*{ENCODED_INT: 2074}*/:
                return 31;
            case ecdsa_brainpoolP384r1tls13_sha384 /*{ENCODED_INT: 2075}*/:
                return 32;
            case ecdsa_brainpoolP512r1tls13_sha512 /*{ENCODED_INT: 2076}*/:
                return 33;
            default:
                return -1;
        }
    }

    public static int getRSAPSSCryptoHashAlgorithm(int signatureScheme) {
        switch (signatureScheme) {
            case rsa_pss_rsae_sha256 /*{ENCODED_INT: 2052}*/:
            case rsa_pss_pss_sha256 /*{ENCODED_INT: 2057}*/:
                return 4;
            case rsa_pss_rsae_sha384 /*{ENCODED_INT: 2053}*/:
            case rsa_pss_pss_sha384 /*{ENCODED_INT: 2058}*/:
                return 5;
            case rsa_pss_rsae_sha512 /*{ENCODED_INT: 2054}*/:
            case rsa_pss_pss_sha512 /*{ENCODED_INT: 2059}*/:
                return 6;
            case ed25519 /*{ENCODED_INT: 2055}*/:
            case ed448 /*{ENCODED_INT: 2056}*/:
            default:
                return -1;
        }
    }

    public static short getHashAlgorithm(int signatureScheme) {
        return (short) ((signatureScheme >>> 8) & CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    public static short getSignatureAlgorithm(int signatureScheme) {
        return (short) (signatureScheme & CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(int signatureScheme) {
        return SignatureAndHashAlgorithm.getInstance(getHashAlgorithm(signatureScheme), getSignatureAlgorithm(signatureScheme));
    }

    public static String getText(int signatureScheme) {
        return getName(signatureScheme) + "(0x" + Integer.toHexString(signatureScheme) + ")";
    }

    public static boolean isPrivate(int signatureScheme) {
        return (signatureScheme >>> 9) == 254;
    }

    public static boolean isECDSA(int signatureScheme) {
        switch (signatureScheme) {
            case ecdsa_brainpoolP256r1tls13_sha256 /*{ENCODED_INT: 2074}*/:
            case ecdsa_brainpoolP384r1tls13_sha384 /*{ENCODED_INT: 2075}*/:
            case ecdsa_brainpoolP512r1tls13_sha512 /*{ENCODED_INT: 2076}*/:
                return true;
            default:
                return 3 == getSignatureAlgorithm(signatureScheme);
        }
    }

    public static boolean isRSAPSS(int signatureScheme) {
        switch (signatureScheme) {
            case rsa_pss_rsae_sha256 /*{ENCODED_INT: 2052}*/:
            case rsa_pss_rsae_sha384 /*{ENCODED_INT: 2053}*/:
            case rsa_pss_rsae_sha512 /*{ENCODED_INT: 2054}*/:
            case rsa_pss_pss_sha256 /*{ENCODED_INT: 2057}*/:
            case rsa_pss_pss_sha384 /*{ENCODED_INT: 2058}*/:
            case rsa_pss_pss_sha512 /*{ENCODED_INT: 2059}*/:
                return true;
            case ed25519 /*{ENCODED_INT: 2055}*/:
            case ed448 /*{ENCODED_INT: 2056}*/:
            default:
                return false;
        }
    }
}
