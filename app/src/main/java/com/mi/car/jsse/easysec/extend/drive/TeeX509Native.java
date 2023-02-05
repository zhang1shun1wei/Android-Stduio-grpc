package com.mi.car.jsse.easysec.extend.drive;

public class TeeX509Native {
    public static native byte[] generateSignatureJNI(byte[] bArr);

    public static native String getIdentityCertJNI();

    public static native String getX509CertChainJNI();

    static {
        System.loadLibrary("cn_x509_jni");
    }
}
