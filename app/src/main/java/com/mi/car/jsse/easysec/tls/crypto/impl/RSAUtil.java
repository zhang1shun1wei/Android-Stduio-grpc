package com.mi.car.jsse.easysec.tls.crypto.impl;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Null;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.RSASSAPSSparams;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.X509ObjectIdentifiers;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public class RSAUtil {
    private static final byte[] RSAPSSParams_256_A;
    private static final byte[] RSAPSSParams_256_B;
    private static final byte[] RSAPSSParams_384_A;
    private static final byte[] RSAPSSParams_384_B;
    private static final byte[] RSAPSSParams_512_A;
    private static final byte[] RSAPSSParams_512_B;

    static {
        AlgorithmIdentifier sha256Identifier_A = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        AlgorithmIdentifier sha384Identifier_A = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
        AlgorithmIdentifier sha512Identifier_A = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
        AlgorithmIdentifier sha256Identifier_B = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        AlgorithmIdentifier sha384Identifier_B = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE);
        AlgorithmIdentifier sha512Identifier_B = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE);
        AlgorithmIdentifier mgf1SHA256Identifier_A = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256Identifier_A);
        AlgorithmIdentifier mgf1SHA384Identifier_A = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha384Identifier_A);
        AlgorithmIdentifier mgf1SHA512Identifier_A = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha512Identifier_A);
        AlgorithmIdentifier mgf1SHA256Identifier_B = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256Identifier_B);
        AlgorithmIdentifier mgf1SHA384Identifier_B = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha384Identifier_B);
        AlgorithmIdentifier mgf1SHA512Identifier_B = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha512Identifier_B);
        ASN1Integer sha256Size = new ASN1Integer((long) TlsCryptoUtils.getHashOutputSize(4));
        ASN1Integer sha384Size = new ASN1Integer((long) TlsCryptoUtils.getHashOutputSize(5));
        ASN1Integer sha512Size = new ASN1Integer((long) TlsCryptoUtils.getHashOutputSize(6));
        ASN1Integer trailerField = new ASN1Integer(1);
        try {
            RSAPSSParams_256_A = new RSASSAPSSparams(sha256Identifier_A, mgf1SHA256Identifier_A, sha256Size, trailerField).getEncoded("DER");
            RSAPSSParams_384_A = new RSASSAPSSparams(sha384Identifier_A, mgf1SHA384Identifier_A, sha384Size, trailerField).getEncoded("DER");
            RSAPSSParams_512_A = new RSASSAPSSparams(sha512Identifier_A, mgf1SHA512Identifier_A, sha512Size, trailerField).getEncoded("DER");
            RSAPSSParams_256_B = new RSASSAPSSparams(sha256Identifier_B, mgf1SHA256Identifier_B, sha256Size, trailerField).getEncoded("DER");
            RSAPSSParams_384_B = new RSASSAPSSparams(sha384Identifier_B, mgf1SHA384Identifier_B, sha384Size, trailerField).getEncoded("DER");
            RSAPSSParams_512_B = new RSASSAPSSparams(sha512Identifier_B, mgf1SHA512Identifier_B, sha512Size, trailerField).getEncoded("DER");
        } catch (IOException e) {
            throw new IllegalStateException(e.getMessage());
        }
    }

    public static boolean supportsPKCS1(AlgorithmIdentifier pubKeyAlgID) {
        ASN1ObjectIdentifier oid = pubKeyAlgID.getAlgorithm();
        return PKCSObjectIdentifiers.rsaEncryption.equals(oid) || X509ObjectIdentifiers.id_ea_rsa.equals(oid);
    }

    public static boolean supportsPSS_PSS(short signatureAlgorithm, AlgorithmIdentifier pubKeyAlgID) {
        byte[] expected_A;
        byte[] expected_B;
        if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(pubKeyAlgID.getAlgorithm())) {
            return false;
        }
        ASN1Encodable pssParams = pubKeyAlgID.getParameters();
        if (pssParams == null || (pssParams instanceof ASN1Null)) {
            switch (signatureAlgorithm) {
                case 9:
                case 10:
                case 11:
                    return true;
                default:
                    return false;
            }
        } else {
            try {
                byte[] encoded = pssParams.toASN1Primitive().getEncoded("DER");
                switch (signatureAlgorithm) {
                    case 9:
                        expected_A = RSAPSSParams_256_A;
                        expected_B = RSAPSSParams_256_B;
                        break;
                    case 10:
                        expected_A = RSAPSSParams_384_A;
                        expected_B = RSAPSSParams_384_B;
                        break;
                    case 11:
                        expected_A = RSAPSSParams_512_A;
                        expected_B = RSAPSSParams_512_B;
                        break;
                    default:
                        return false;
                }
                return Arrays.areEqual(expected_A, encoded) || Arrays.areEqual(expected_B, encoded);
            } catch (Exception e) {
                return false;
            }
        }
    }

    public static boolean supportsPSS_RSAE(AlgorithmIdentifier pubKeyAlgID) {
        return PKCSObjectIdentifiers.rsaEncryption.equals(pubKeyAlgID.getAlgorithm());
    }
}
