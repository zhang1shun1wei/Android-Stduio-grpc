package com.mi.car.jsse.easysec.tls;

public class HashAlgorithm {
    public static final short Intrinsic = 8;
    public static final short md5 = 1;
    public static final short none = 0;
    public static final short sha1 = 2;
    public static final short sha224 = 3;
    public static final short sha256 = 4;
    public static final short sha384 = 5;
    public static final short sha512 = 6;

    public static String getName(short hashAlgorithm) {
        switch (hashAlgorithm) {
            case 0:
                return "none";
            case 1:
                return "md5";
            case 2:
                return "sha1";
            case 3:
                return "sha224";
            case 4:
                return "sha256";
            case 5:
                return "sha384";
            case 6:
                return "sha512";
            case 7:
            default:
                return "UNKNOWN";
            case 8:
                return "Intrinsic";
        }
    }

    public static int getOutputSize(short hashAlgorithm) {
        switch (hashAlgorithm) {
            case 1:
                return 16;
            case 2:
                return 20;
            case 3:
                return 28;
            case 4:
                return 32;
            case 5:
                return 48;
            case 6:
                return 64;
            default:
                return -1;
        }
    }

    public static String getText(short hashAlgorithm) {
        return getName(hashAlgorithm) + "(" + ((int) hashAlgorithm) + ")";
    }

    public static boolean isPrivate(short hashAlgorithm) {
        return 224 <= hashAlgorithm && hashAlgorithm <= 255;
    }

    public static boolean isRecognized(short hashAlgorithm) {
        switch (hashAlgorithm) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 8:
                return true;
            case 7:
            default:
                return false;
        }
    }
}
