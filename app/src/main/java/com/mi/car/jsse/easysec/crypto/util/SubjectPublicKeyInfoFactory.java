package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Null;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import com.mi.car.jsse.easysec.asn1.edec.EdECObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.RSAPublicKey;
import com.mi.car.jsse.easysec.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.DSAParameter;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.asn1.x9.X962Parameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECPoint;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DSAParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECGOST3410Parameters;
import com.mi.car.jsse.easysec.crypto.params.ECNamedDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed25519PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed448PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.X25519PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.X448PublicKeyParameters;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

public class SubjectPublicKeyInfoFactory {
    private static Set cryptoProOids = new HashSet(5);

    static {
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB);
    }

    private SubjectPublicKeyInfoFactory() {
    }

    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) throws IOException {
        ASN1Encodable params;
        int encKeySize;
        int offset;
        ASN1ObjectIdentifier algIdentifier;
        if (publicKey instanceof RSAKeyParameters) {
            RSAKeyParameters pub = (RSAKeyParameters) publicKey;
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(pub.getModulus(), pub.getExponent()));
        } else if (publicKey instanceof DSAPublicKeyParameters) {
            DSAPublicKeyParameters pub2 = (DSAPublicKeyParameters) publicKey;
            DSAParameter params2 = null;
            DSAParameters dsaParams = pub2.getParameters();
            if (dsaParams != null) {
                params2 = new DSAParameter(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
            }
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, params2), new ASN1Integer(pub2.getY()));
        } else if (publicKey instanceof ECPublicKeyParameters) {
            ECPublicKeyParameters pub3 = (ECPublicKeyParameters) publicKey;
            ECDomainParameters domainParams = pub3.getParameters();
            if (domainParams == null) {
                params = new X962Parameters((ASN1Null) DERNull.INSTANCE);
            } else if (domainParams instanceof ECGOST3410Parameters) {
                ECGOST3410Parameters gostParams = (ECGOST3410Parameters) domainParams;
                BigInteger bX = pub3.getQ().getAffineXCoord().toBigInteger();
                BigInteger bY = pub3.getQ().getAffineYCoord().toBigInteger();
                ASN1Encodable params3 = new GOST3410PublicKeyAlgParameters(gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet());
                if (cryptoProOids.contains(gostParams.getPublicKeyParamSet())) {
                    encKeySize = 64;
                    offset = 32;
                    algIdentifier = CryptoProObjectIdentifiers.gostR3410_2001;
                } else {
                    if (bX.bitLength() > 256) {
                        encKeySize = 128;
                        offset = 64;
                        algIdentifier = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512;
                    } else {
                        encKeySize = 64;
                        offset = 32;
                        algIdentifier = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
                    }
                }
                byte[] encKey = new byte[encKeySize];
                extractBytes(encKey, encKeySize / 2, 0, bX);
                extractBytes(encKey, encKeySize / 2, offset, bY);
                try {
                    return new SubjectPublicKeyInfo(new AlgorithmIdentifier(algIdentifier, params3), new DEROctetString(encKey));
                } catch (IOException e) {
                    return null;
                }
            } else if (domainParams instanceof ECNamedDomainParameters) {
                params = new X962Parameters(((ECNamedDomainParameters) domainParams).getName());
            } else {
                params = new X962Parameters(new X9ECParameters(domainParams.getCurve(), new X9ECPoint(domainParams.getG(), false), domainParams.getN(), domainParams.getH(), domainParams.getSeed()));
            }
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), pub3.getQ().getEncoded(false));
        } else if (publicKey instanceof X448PublicKeyParameters) {
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448), ((X448PublicKeyParameters) publicKey).getEncoded());
        } else {
            if (publicKey instanceof X25519PublicKeyParameters) {
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), ((X25519PublicKeyParameters) publicKey).getEncoded());
            }
            if (publicKey instanceof Ed448PublicKeyParameters) {
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448), ((Ed448PublicKeyParameters) publicKey).getEncoded());
            }
            if (publicKey instanceof Ed25519PublicKeyParameters) {
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), ((Ed25519PublicKeyParameters) publicKey).getEncoded());
            }
            throw new IOException("key parameters not recognized");
        }
    }

    private static void extractBytes(byte[] encKey, int size, int offSet, BigInteger bI) {
        byte[] val = bI.toByteArray();
        if (val.length < size) {
            byte[] tmp = new byte[size];
            System.arraycopy(val, 0, tmp, tmp.length - val.length, val.length);
            val = tmp;
        }
        for (int i = 0; i != size; i++) {
            encKey[offSet + i] = val[(val.length - 1) - i];
        }
    }
}
