package com.mi.car.jsse.easysec.pqc.jcajce.provider.util;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Encoding;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;

public class KeyUtil {
    public static byte[] getEncodedSubjectPublicKeyInfo(AlgorithmIdentifier algId, ASN1Encodable keyData) {
        try {
            return getEncodedSubjectPublicKeyInfo(new SubjectPublicKeyInfo(algId, keyData));
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] getEncodedSubjectPublicKeyInfo(AlgorithmIdentifier algId, byte[] keyData) {
        try {
            return getEncodedSubjectPublicKeyInfo(new SubjectPublicKeyInfo(algId, keyData));
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] getEncodedSubjectPublicKeyInfo(SubjectPublicKeyInfo info) {
        try {
            return info.getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] getEncodedPrivateKeyInfo(AlgorithmIdentifier algId, ASN1Encodable privKey) {
        try {
            return getEncodedPrivateKeyInfo(new PrivateKeyInfo(algId, privKey.toASN1Primitive()));
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] getEncodedPrivateKeyInfo(PrivateKeyInfo info) {
        try {
            return info.getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            return null;
        }
    }
}