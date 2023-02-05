package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Null;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.RSASSAPSSparams;
import com.mi.car.jsse.easysec.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PSSParameterSpec;

/* access modifiers changed from: package-private */
public class X509SignatureUtil {
    private static final ASN1Null derNull = DERNull.INSTANCE;

    X509SignatureUtil() {
    }

    static void setSignatureParameters(Signature signature, ASN1Encodable params) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        if (params != null && !derNull.equals(params)) {
            AlgorithmParameters sigParams = AlgorithmParameters.getInstance(signature.getAlgorithm(), signature.getProvider());
            try {
                sigParams.init(params.toASN1Primitive().getEncoded());
                if (signature.getAlgorithm().endsWith("MGF1")) {
                    try {
                        signature.setParameter(sigParams.getParameterSpec(PSSParameterSpec.class));
                    } catch (GeneralSecurityException e) {
                        throw new SignatureException("Exception extracting parameters: " + e.getMessage());
                    }
                }
            } catch (IOException e2) {
                throw new SignatureException("IOException decoding parameters: " + e2.getMessage());
            }
        }
    }

    static String getSignatureName(AlgorithmIdentifier sigAlgId) {
        ASN1Encodable params = sigAlgId.getParameters();
        if (params != null && !derNull.equals(params)) {
            if (sigAlgId.getAlgorithm().equals((ASN1Primitive) PKCSObjectIdentifiers.id_RSASSA_PSS)) {
                return getDigestAlgName(RSASSAPSSparams.getInstance(params).getHashAlgorithm().getAlgorithm()) + "withRSAandMGF1";
            } else if (sigAlgId.getAlgorithm().equals((ASN1Primitive) X9ObjectIdentifiers.ecdsa_with_SHA2)) {
                return getDigestAlgName(ASN1ObjectIdentifier.getInstance(ASN1Sequence.getInstance(params).getObjectAt(0))) + "withECDSA";
            }
        }
        return sigAlgId.getAlgorithm().getId();
    }

    private static String getDigestAlgName(ASN1ObjectIdentifier digestAlgOID) {
        if (PKCSObjectIdentifiers.md5.equals((ASN1Primitive) digestAlgOID)) {
            return "MD5";
        }
        if (OIWObjectIdentifiers.idSHA1.equals((ASN1Primitive) digestAlgOID)) {
            return "SHA1";
        }
        if (NISTObjectIdentifiers.id_sha224.equals((ASN1Primitive) digestAlgOID)) {
            return "SHA224";
        }
        if (NISTObjectIdentifiers.id_sha256.equals((ASN1Primitive) digestAlgOID)) {
            return "SHA256";
        }
        if (NISTObjectIdentifiers.id_sha384.equals((ASN1Primitive) digestAlgOID)) {
            return "SHA384";
        }
        if (NISTObjectIdentifiers.id_sha512.equals((ASN1Primitive) digestAlgOID)) {
            return "SHA512";
        }
        if (TeleTrusTObjectIdentifiers.ripemd128.equals((ASN1Primitive) digestAlgOID)) {
            return "RIPEMD128";
        }
        if (TeleTrusTObjectIdentifiers.ripemd160.equals((ASN1Primitive) digestAlgOID)) {
            return "RIPEMD160";
        }
        if (TeleTrusTObjectIdentifiers.ripemd256.equals((ASN1Primitive) digestAlgOID)) {
            return "RIPEMD256";
        }
        if (CryptoProObjectIdentifiers.gostR3411.equals((ASN1Primitive) digestAlgOID)) {
            return "GOST3411";
        }
        return digestAlgOID.getId();
    }
}
