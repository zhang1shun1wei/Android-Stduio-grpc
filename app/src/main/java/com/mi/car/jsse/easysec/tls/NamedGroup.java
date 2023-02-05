package com.mi.car.jsse.easysec.tls;

public class NamedGroup {
    private static final String[] CURVE_NAMES = {"sect163k1", "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1", "sect571r1", "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "secp224k1", "secp224r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "X25519", "X448", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "Tc26-Gost-3410-12-256-paramSetA", "GostR3410-2001-CryptoPro-A", "GostR3410-2001-CryptoPro-B", "GostR3410-2001-CryptoPro-C", "Tc26-Gost-3410-12-512-paramSetA", "Tc26-Gost-3410-12-512-paramSetB", "Tc26-Gost-3410-12-512-paramSetC", "sm2p256v1"};
    private static final String[] FINITE_FIELD_NAMES = {"ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192"};
    public static final int GC256A = 34;
    public static final int GC256B = 35;
    public static final int GC256C = 36;
    public static final int GC256D = 37;
    public static final int GC512A = 38;
    public static final int GC512B = 39;
    public static final int GC512C = 40;
    public static final int arbitrary_explicit_char2_curves = 65282;
    public static final int arbitrary_explicit_prime_curves = 65281;
    public static final int brainpoolP256r1 = 26;
    public static final int brainpoolP256r1tls13 = 31;
    public static final int brainpoolP384r1 = 27;
    public static final int brainpoolP384r1tls13 = 32;
    public static final int brainpoolP512r1 = 28;
    public static final int brainpoolP512r1tls13 = 33;
    public static final int curveSM2 = 41;
    public static final int ffdhe2048 = 256;
    public static final int ffdhe3072 = 257;
    public static final int ffdhe4096 = 258;
    public static final int ffdhe6144 = 259;
    public static final int ffdhe8192 = 260;
    public static final int secp160k1 = 15;
    public static final int secp160r1 = 16;
    public static final int secp160r2 = 17;
    public static final int secp192k1 = 18;
    public static final int secp192r1 = 19;
    public static final int secp224k1 = 20;
    public static final int secp224r1 = 21;
    public static final int secp256k1 = 22;
    public static final int secp256r1 = 23;
    public static final int secp384r1 = 24;
    public static final int secp521r1 = 25;
    public static final int sect163k1 = 1;
    public static final int sect163r1 = 2;
    public static final int sect163r2 = 3;
    public static final int sect193r1 = 4;
    public static final int sect193r2 = 5;
    public static final int sect233k1 = 6;
    public static final int sect233r1 = 7;
    public static final int sect239k1 = 8;
    public static final int sect283k1 = 9;
    public static final int sect283r1 = 10;
    public static final int sect409k1 = 11;
    public static final int sect409r1 = 12;
    public static final int sect571k1 = 13;
    public static final int sect571r1 = 14;
    public static final int x25519 = 29;
    public static final int x448 = 30;

    public static boolean canBeNegotiated(int namedGroup, ProtocolVersion version) {
        if (TlsUtils.isTLSv13(version)) {
            if (namedGroup >= 1 && namedGroup <= 22) {
                return false;
            }
            if (namedGroup >= 26 && namedGroup <= 28) {
                return false;
            }
            if (namedGroup >= 34 && namedGroup <= 40) {
                return false;
            }
            if (namedGroup >= 65281 && namedGroup <= 65282) {
                return false;
            }
        } else if ((namedGroup >= 31 && namedGroup <= 33) || namedGroup == 41) {
            return false;
        }
        return isValid(namedGroup);
    }

    public static int getCurveBits(int namedGroup) {
        switch (namedGroup) {
            case 1:
            case 2:
            case 3:
                return CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384;
            case 4:
            case 5:
                return CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256;
            case 6:
            case 7:
                return 233;
            case 8:
                return 239;
            case 9:
            case 10:
                return 283;
            case 11:
            case 12:
                return 409;
            case 13:
            case 14:
                return 571;
            case 15:
            case 16:
            case 17:
                return CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256;
            case 18:
            case 19:
                return CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256;
            case 20:
            case 21:
                return 224;
            case 22:
            case 23:
            case 26:
            case brainpoolP256r1tls13 /*{ENCODED_INT: 31}*/:
            case GC256A /*{ENCODED_INT: 34}*/:
            case 35:
            case GC256C /*{ENCODED_INT: 36}*/:
            case GC256D /*{ENCODED_INT: 37}*/:
            case 41:
                return ffdhe2048;
            case 24:
            case 27:
            case brainpoolP384r1tls13 /*{ENCODED_INT: 32}*/:
                return 384;
            case 25:
                return 521;
            case 28:
            case brainpoolP512r1tls13 /*{ENCODED_INT: 33}*/:
            case GC512A /*{ENCODED_INT: 38}*/:
            case GC512B /*{ENCODED_INT: 39}*/:
            case GC512C /*{ENCODED_INT: 40}*/:
                return 512;
            case x25519 /*{ENCODED_INT: 29}*/:
                return 252;
            case x448 /*{ENCODED_INT: 30}*/:
                return 446;
            default:
                return 0;
        }
    }

    public static String getCurveName(int namedGroup) {
        if (refersToASpecificCurve(namedGroup)) {
            return CURVE_NAMES[namedGroup - 1];
        }
        return null;
    }

    public static int getFiniteFieldBits(int namedGroup) {
        switch (namedGroup) {
            case ffdhe2048 /*{ENCODED_INT: 256}*/:
                return DefaultTlsDHGroupVerifier.DEFAULT_MINIMUM_PRIME_BITS;
            case ffdhe3072 /*{ENCODED_INT: 257}*/:
                return 3072;
            case ffdhe4096 /*{ENCODED_INT: 258}*/:
                return 4096;
            case ffdhe6144 /*{ENCODED_INT: 259}*/:
                return 6144;
            case ffdhe8192 /*{ENCODED_INT: 260}*/:
                return 8192;
            default:
                return 0;
        }
    }

    public static String getFiniteFieldName(int namedGroup) {
        if (refersToASpecificFiniteField(namedGroup)) {
            return FINITE_FIELD_NAMES[namedGroup - 256];
        }
        return null;
    }

    public static int getMaximumChar2CurveBits() {
        return 571;
    }

    public static int getMaximumCurveBits() {
        return 571;
    }

    public static int getMaximumFiniteFieldBits() {
        return 8192;
    }

    public static int getMaximumPrimeCurveBits() {
        return 521;
    }

    public static String getName(int namedGroup) {
        if (isPrivate(namedGroup)) {
            return "PRIVATE";
        }
        switch (namedGroup) {
            case x25519 /*{ENCODED_INT: 29}*/:
                return "x25519";
            case x448 /*{ENCODED_INT: 30}*/:
                return "x448";
            case brainpoolP256r1tls13 /*{ENCODED_INT: 31}*/:
                return "brainpoolP256r1tls13";
            case brainpoolP384r1tls13 /*{ENCODED_INT: 32}*/:
                return "brainpoolP384r1tls13";
            case brainpoolP512r1tls13 /*{ENCODED_INT: 33}*/:
                return "brainpoolP512r1tls13";
            case GC256A /*{ENCODED_INT: 34}*/:
                return "GC256A";
            case 35:
                return "GC256B";
            case GC256C /*{ENCODED_INT: 36}*/:
                return "GC256C";
            case GC256D /*{ENCODED_INT: 37}*/:
                return "GC256D";
            case GC512A /*{ENCODED_INT: 38}*/:
                return "GC512A";
            case GC512B /*{ENCODED_INT: 39}*/:
                return "GC512B";
            case GC512C /*{ENCODED_INT: 40}*/:
                return "GC512C";
            case 41:
                return "curveSM2";
            case 65281:
                return "arbitrary_explicit_prime_curves";
            case arbitrary_explicit_char2_curves /*{ENCODED_INT: 65282}*/:
                return "arbitrary_explicit_char2_curves";
            default:
                String standardName = getStandardName(namedGroup);
                return standardName == null ? "UNKNOWN" : standardName;
        }
    }

    public static String getStandardName(int namedGroup) {
        String curveName = getCurveName(namedGroup);
        if (curveName != null) {
            return curveName;
        }
        String finiteFieldName = getFiniteFieldName(namedGroup);
        if (finiteFieldName != null) {
            return finiteFieldName;
        }
        return null;
    }

    public static String getText(int namedGroup) {
        return getName(namedGroup) + "(" + namedGroup + ")";
    }

    public static boolean isChar2Curve(int namedGroup) {
        return (namedGroup >= 1 && namedGroup <= 14) || namedGroup == 65282;
    }

    public static boolean isPrimeCurve(int namedGroup) {
        return (namedGroup >= 15 && namedGroup <= 41) || namedGroup == 65281;
    }

    public static boolean isPrivate(int namedGroup) {
        return (namedGroup >>> 2) == 127 || (namedGroup >>> 8) == 254;
    }

    public static boolean isValid(int namedGroup) {
        return refersToASpecificGroup(namedGroup) || isPrivate(namedGroup) || (namedGroup >= 65281 && namedGroup <= 65282);
    }

    public static boolean refersToAnECDHCurve(int namedGroup) {
        return refersToASpecificCurve(namedGroup);
    }

    public static boolean refersToAnECDSACurve(int namedGroup) {
        return refersToASpecificCurve(namedGroup) && !refersToAnXDHCurve(namedGroup);
    }

    public static boolean refersToAnXDHCurve(int namedGroup) {
        return namedGroup >= 29 && namedGroup <= 30;
    }

    public static boolean refersToASpecificCurve(int namedGroup) {
        return namedGroup >= 1 && namedGroup <= 41;
    }

    public static boolean refersToASpecificFiniteField(int namedGroup) {
        return namedGroup >= 256 && namedGroup <= 260;
    }

    public static boolean refersToASpecificGroup(int namedGroup) {
        return refersToASpecificCurve(namedGroup) || refersToASpecificFiniteField(namedGroup);
    }
}
