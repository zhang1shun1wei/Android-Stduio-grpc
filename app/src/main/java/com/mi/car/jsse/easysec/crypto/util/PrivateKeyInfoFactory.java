package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Null;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import com.mi.car.jsse.easysec.asn1.edec.EdECObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.pkcs.RSAPrivateKey;
import com.mi.car.jsse.easysec.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.sec.ECPrivateKey;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.DSAParameter;
import com.mi.car.jsse.easysec.asn1.x9.X962Parameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECPoint;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DSAParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECGOST3410Parameters;
import com.mi.car.jsse.easysec.crypto.params.ECNamedDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed25519PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed448PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAPrivateCrtKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.X25519PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.X448PrivateKeyParameters;
import com.mi.car.jsse.easysec.math.ec.FixedPointCombMultiplier;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

public class PrivateKeyInfoFactory {
    private static Set cryptoProOids = new HashSet(5);

    static {
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB);
    }

    private PrivateKeyInfoFactory() {
    }

    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey) throws IOException {
        return createPrivateKeyInfo(privateKey, null);
    }

    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes) throws IOException {
        ASN1Encodable params;
        int orderBitLength;
        ASN1ObjectIdentifier identifier;
        int size;
        if (privateKey instanceof RSAKeyParameters) {
            RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters) privateKey;
            return new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPrivateKey(priv.getModulus(), priv.getPublicExponent(), priv.getExponent(), priv.getP(), priv.getQ(), priv.getDP(), priv.getDQ(), priv.getQInv()), attributes);
        } else if (privateKey instanceof DSAPrivateKeyParameters) {
            DSAPrivateKeyParameters priv2 = (DSAPrivateKeyParameters) privateKey;
            DSAParameters params2 = priv2.getParameters();
            return new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, new DSAParameter(params2.getP(), params2.getQ(), params2.getG())), new ASN1Integer(priv2.getX()), attributes);
        } else if (privateKey instanceof ECPrivateKeyParameters) {
            ECPrivateKeyParameters priv3 = (ECPrivateKeyParameters) privateKey;
            ECDomainParameters domainParams = priv3.getParameters();
            if (domainParams == null) {
                params = new X962Parameters((ASN1Null) DERNull.INSTANCE);
                orderBitLength = priv3.getD().bitLength();
            } else if (domainParams instanceof ECGOST3410Parameters) {
                GOST3410PublicKeyAlgParameters gostParams = new GOST3410PublicKeyAlgParameters(((ECGOST3410Parameters) domainParams).getPublicKeyParamSet(), ((ECGOST3410Parameters) domainParams).getDigestParamSet(), ((ECGOST3410Parameters) domainParams).getEncryptionParamSet());
                if (cryptoProOids.contains(gostParams.getPublicKeyParamSet())) {
                    size = 32;
                    identifier = CryptoProObjectIdentifiers.gostR3410_2001;
                } else {
                    boolean is512 = priv3.getD().bitLength() > 256;
                    identifier = is512 ? RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512 : RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
                    size = is512 ? 64 : 32;
                }
                byte[] encKey = new byte[size];
                extractBytes(encKey, size, 0, priv3.getD());
                return new PrivateKeyInfo(new AlgorithmIdentifier(identifier, gostParams), new DEROctetString(encKey));
            } else if (domainParams instanceof ECNamedDomainParameters) {
                params = new X962Parameters(((ECNamedDomainParameters) domainParams).getName());
                orderBitLength = domainParams.getN().bitLength();
            } else {
                params = new X962Parameters(new X9ECParameters(domainParams.getCurve(), new X9ECPoint(domainParams.getG(), false), domainParams.getN(), domainParams.getH(), domainParams.getSeed()));
                orderBitLength = domainParams.getN().bitLength();
            }
            return new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), new ECPrivateKey(orderBitLength, priv3.getD(), new DERBitString(new FixedPointCombMultiplier().multiply(domainParams.getG(), priv3.getD()).getEncoded(false)), params), attributes);
        } else if (privateKey instanceof X448PrivateKeyParameters) {
            X448PrivateKeyParameters key = (X448PrivateKeyParameters) privateKey;
            return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448), new DEROctetString(key.getEncoded()), attributes, key.generatePublicKey().getEncoded());
        } else if (privateKey instanceof X25519PrivateKeyParameters) {
            X25519PrivateKeyParameters key2 = (X25519PrivateKeyParameters) privateKey;
            return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), new DEROctetString(key2.getEncoded()), attributes, key2.generatePublicKey().getEncoded());
        } else if (privateKey instanceof Ed448PrivateKeyParameters) {
            Ed448PrivateKeyParameters key3 = (Ed448PrivateKeyParameters) privateKey;
            return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448), new DEROctetString(key3.getEncoded()), attributes, key3.generatePublicKey().getEncoded());
        } else if (privateKey instanceof Ed25519PrivateKeyParameters) {
            Ed25519PrivateKeyParameters key4 = (Ed25519PrivateKeyParameters) privateKey;
            return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), new DEROctetString(key4.getEncoded()), attributes, key4.generatePublicKey().getEncoded());
        } else {
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
