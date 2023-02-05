package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1InputStream;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.cryptopro.ECGOST3410NamedCurves;
import com.mi.car.jsse.easysec.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import com.mi.car.jsse.easysec.asn1.edec.EdECObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.oiw.ElGamalParameter;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.DHParameter;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.pkcs.RSAPrivateKey;
import com.mi.car.jsse.easysec.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.sec.ECPrivateKey;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.DSAParameter;
import com.mi.car.jsse.easysec.asn1.x509.X509ObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x9.ECNamedCurveTable;
import com.mi.car.jsse.easysec.asn1.x9.X962Parameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.ec.CustomNamedCurves;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECGOST3410Parameters;
import com.mi.car.jsse.easysec.crypto.params.ECNamedDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed25519PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed448PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ElGamalParameters;
import com.mi.car.jsse.easysec.crypto.params.ElGamalPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAPrivateCrtKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.X25519PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.X448PrivateKeyParameters;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

public class PrivateKeyFactory {
    public static AsymmetricKeyParameter createKey(byte[] privateKeyInfoData) throws IOException {
        return createKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privateKeyInfoData)));
    }

    public static AsymmetricKeyParameter createKey(InputStream inStr) throws IOException {
        return createKey(PrivateKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
    }

    public static AsymmetricKeyParameter createKey(PrivateKeyInfo keyInfo) throws IOException {
        ECGOST3410Parameters ecSpec;
        BigInteger d;
        ECDomainParameters dParams;
        AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();
        if (algOID.equals((ASN1Primitive) PKCSObjectIdentifiers.rsaEncryption) || algOID.equals((ASN1Primitive) PKCSObjectIdentifiers.id_RSASSA_PSS) || algOID.equals((ASN1Primitive) X509ObjectIdentifiers.id_ea_rsa)) {
            RSAPrivateKey keyStructure = RSAPrivateKey.getInstance(keyInfo.parsePrivateKey());
            return new RSAPrivateCrtKeyParameters(keyStructure.getModulus(), keyStructure.getPublicExponent(), keyStructure.getPrivateExponent(), keyStructure.getPrime1(), keyStructure.getPrime2(), keyStructure.getExponent1(), keyStructure.getExponent2(), keyStructure.getCoefficient());
        } else if (algOID.equals((ASN1Primitive) PKCSObjectIdentifiers.dhKeyAgreement)) {
            DHParameter params = DHParameter.getInstance(algId.getParameters());
            ASN1Integer derX = (ASN1Integer) keyInfo.parsePrivateKey();
            BigInteger lVal = params.getL();
            return new DHPrivateKeyParameters(derX.getValue(), new DHParameters(params.getP(), params.getG(), null, lVal == null ? 0 : lVal.intValue()));
        } else if (algOID.equals((ASN1Primitive) OIWObjectIdentifiers.elGamalAlgorithm)) {
            ElGamalParameter params2 = ElGamalParameter.getInstance(algId.getParameters());
            return new ElGamalPrivateKeyParameters(((ASN1Integer) keyInfo.parsePrivateKey()).getValue(), new ElGamalParameters(params2.getP(), params2.getG()));
        } else if (algOID.equals((ASN1Primitive) X9ObjectIdentifiers.id_dsa)) {
            ASN1Integer derX2 = (ASN1Integer) keyInfo.parsePrivateKey();
            ASN1Encodable algParameters = algId.getParameters();
            DSAParameters parameters = null;
            if (algParameters != null) {
                DSAParameter params3 = DSAParameter.getInstance(algParameters.toASN1Primitive());
                parameters = new DSAParameters(params3.getP(), params3.getQ(), params3.getG());
            }
            return new DSAPrivateKeyParameters(derX2.getValue(), parameters);
        } else if (algOID.equals((ASN1Primitive) X9ObjectIdentifiers.id_ecPublicKey)) {
            X962Parameters params4 = X962Parameters.getInstance(algId.getParameters());
            if (params4.isNamedCurve()) {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) params4.getParameters();
                X9ECParameters x9 = CustomNamedCurves.getByOID(oid);
                if (x9 == null) {
                    x9 = ECNamedCurveTable.getByOID(oid);
                }
                dParams = new ECNamedDomainParameters(oid, x9);
            } else {
                X9ECParameters x92 = X9ECParameters.getInstance(params4.getParameters());
                dParams = new ECDomainParameters(x92.getCurve(), x92.getG(), x92.getN(), x92.getH(), x92.getSeed());
            }
            return new ECPrivateKeyParameters(ECPrivateKey.getInstance(keyInfo.parsePrivateKey()).getKey(), dParams);
        } else if (algOID.equals((ASN1Primitive) EdECObjectIdentifiers.id_X25519)) {
            return new X25519PrivateKeyParameters(getRawKey(keyInfo));
        } else {
            if (algOID.equals((ASN1Primitive) EdECObjectIdentifiers.id_X448)) {
                return new X448PrivateKeyParameters(getRawKey(keyInfo));
            }
            if (algOID.equals((ASN1Primitive) EdECObjectIdentifiers.id_Ed25519)) {
                return new Ed25519PrivateKeyParameters(getRawKey(keyInfo));
            }
            if (algOID.equals((ASN1Primitive) EdECObjectIdentifiers.id_Ed448)) {
                return new Ed448PrivateKeyParameters(getRawKey(keyInfo));
            }
            if (algOID.equals((ASN1Primitive) CryptoProObjectIdentifiers.gostR3410_2001) || algOID.equals((ASN1Primitive) RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512) || algOID.equals((ASN1Primitive) RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256)) {
                ASN1Encodable algParameters2 = algId.getParameters();
                GOST3410PublicKeyAlgParameters gostParams = GOST3410PublicKeyAlgParameters.getInstance(algParameters2);
                ASN1Primitive p = algParameters2.toASN1Primitive();
                if (!(p instanceof ASN1Sequence) || !(ASN1Sequence.getInstance(p).size() == 2 || ASN1Sequence.getInstance(p).size() == 3)) {
                    X962Parameters params5 = X962Parameters.getInstance(algId.getParameters());
                    if (params5.isNamedCurve()) {
                        ASN1ObjectIdentifier oid2 = ASN1ObjectIdentifier.getInstance(params5.getParameters());
                        ecSpec = new ECGOST3410Parameters(new ECNamedDomainParameters(oid2, ECNamedCurveTable.getByOID(oid2)), gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet(), gostParams.getEncryptionParamSet());
                    } else if (params5.isImplicitlyCA()) {
                        ecSpec = null;
                    } else {
                        ecSpec = new ECGOST3410Parameters(new ECNamedDomainParameters(algOID, X9ECParameters.getInstance(params5.getParameters())), gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet(), gostParams.getEncryptionParamSet());
                    }
                    ASN1Encodable privKey = keyInfo.parsePrivateKey();
                    if (privKey instanceof ASN1Integer) {
                        d = ASN1Integer.getInstance(privKey).getValue();
                    } else {
                        d = ECPrivateKey.getInstance(privKey).getKey();
                    }
                } else {
                    ecSpec = new ECGOST3410Parameters(new ECNamedDomainParameters(gostParams.getPublicKeyParamSet(), ECGOST3410NamedCurves.getByOIDX9(gostParams.getPublicKeyParamSet())), gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet(), gostParams.getEncryptionParamSet());
                    ASN1OctetString privEnc = keyInfo.getPrivateKey();
                    if (privEnc.getOctets().length == 32 || privEnc.getOctets().length == 64) {
                        d = new BigInteger(1, Arrays.reverse(privEnc.getOctets()));
                    } else {
                        ASN1Encodable privKey2 = keyInfo.parsePrivateKey();
                        if (privKey2 instanceof ASN1Integer) {
                            d = ASN1Integer.getInstance(privKey2).getPositiveValue();
                        } else {
                            d = new BigInteger(1, Arrays.reverse(ASN1OctetString.getInstance(privKey2).getOctets()));
                        }
                    }
                }
                return new ECPrivateKeyParameters(d, new ECGOST3410Parameters(ecSpec, gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet(), gostParams.getEncryptionParamSet()));
            }
            throw new RuntimeException("algorithm identifier in private key not recognised");
        }
    }

    private static byte[] getRawKey(PrivateKeyInfo keyInfo) throws IOException {
        return ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
    }
}
