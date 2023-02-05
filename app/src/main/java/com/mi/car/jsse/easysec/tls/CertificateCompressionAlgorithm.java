package com.mi.car.jsse.easysec.tls;

public class CertificateCompressionAlgorithm {
    public static final int brotli = 2;
    public static final int zlib = 1;
    public static final int zstd = 3;

    public static String getName(int certificateCompressionAlgorithm) {
        switch (certificateCompressionAlgorithm) {
            case 1:
                return "zlib";
            case 2:
                return "brotli";
            case 3:
                return "zstd";
            default:
                return "UNKNOWN";
        }
    }

    public static String getText(int certificateCompressionAlgorithm) {
        return getName(certificateCompressionAlgorithm) + "(" + certificateCompressionAlgorithm + ")";
    }

    public static boolean isRecognized(int certificateCompressionAlgorithm) {
        switch (certificateCompressionAlgorithm) {
            case 1:
            case 2:
            case 3:
                return true;
            default:
                return false;
        }
    }
}
