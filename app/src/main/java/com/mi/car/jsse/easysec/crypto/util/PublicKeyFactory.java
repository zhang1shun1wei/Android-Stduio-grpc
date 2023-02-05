package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1InputStream;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.cryptopro.ECGOST3410NamedCurves;
import com.mi.car.jsse.easysec.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import com.mi.car.jsse.easysec.asn1.edec.EdECObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.oiw.ElGamalParameter;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.DHParameter;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.RSAPublicKey;
import com.mi.car.jsse.easysec.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.ua.DSTU4145BinaryField;
import com.mi.car.jsse.easysec.asn1.ua.DSTU4145ECBinary;
import com.mi.car.jsse.easysec.asn1.ua.DSTU4145NamedCurves;
import com.mi.car.jsse.easysec.asn1.ua.DSTU4145Params;
import com.mi.car.jsse.easysec.asn1.ua.DSTU4145PointEncoder;
import com.mi.car.jsse.easysec.asn1.ua.UAObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.DSAParameter;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.X509ObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x9.DHPublicKey;
import com.mi.car.jsse.easysec.asn1.x9.DomainParameters;
import com.mi.car.jsse.easysec.asn1.x9.ECNamedCurveTable;
import com.mi.car.jsse.easysec.asn1.x9.ValidationParams;
import com.mi.car.jsse.easysec.asn1.x9.X962Parameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ECPoint;
import com.mi.car.jsse.easysec.asn1.x9.X9IntegerConverter;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.ec.CustomNamedCurves;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.crypto.params.DHPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.DHValidationParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECGOST3410Parameters;
import com.mi.car.jsse.easysec.crypto.params.ECNamedDomainParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed25519PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed448PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ElGamalParameters;
import com.mi.car.jsse.easysec.crypto.params.ElGamalPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.X25519PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.X448PublicKeyParameters;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class PublicKeyFactory {
    private static Map converters = new HashMap();

    static {
        converters.put(PKCSObjectIdentifiers.rsaEncryption, new RSAConverter());
        converters.put(PKCSObjectIdentifiers.id_RSASSA_PSS, new RSAConverter());
        converters.put(X509ObjectIdentifiers.id_ea_rsa, new RSAConverter());
        converters.put(X9ObjectIdentifiers.dhpublicnumber, new DHPublicNumberConverter());
        converters.put(PKCSObjectIdentifiers.dhKeyAgreement, new DHAgreementConverter());
        converters.put(X9ObjectIdentifiers.id_dsa, new DSAConverter());
        converters.put(OIWObjectIdentifiers.dsaWithSHA1, new DSAConverter());
        converters.put(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalConverter());
        converters.put(X9ObjectIdentifiers.id_ecPublicKey, new ECConverter());
        converters.put(CryptoProObjectIdentifiers.gostR3410_2001, new GOST3410_2001Converter());
        converters.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, new GOST3410_2012Converter());
        converters.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, new GOST3410_2012Converter());
        converters.put(UAObjectIdentifiers.dstu4145be, new DSTUConverter());
        converters.put(UAObjectIdentifiers.dstu4145le, new DSTUConverter());
        converters.put(EdECObjectIdentifiers.id_X25519, new X25519Converter());
        converters.put(EdECObjectIdentifiers.id_X448, new X448Converter());
        converters.put(EdECObjectIdentifiers.id_Ed25519, new Ed25519Converter());
        converters.put(EdECObjectIdentifiers.id_Ed448, new Ed448Converter());
    }

    public static AsymmetricKeyParameter createKey(byte[] keyInfoData) throws IOException {
        return createKey(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(keyInfoData)));
    }

    public static AsymmetricKeyParameter createKey(InputStream inStr) throws IOException {
        return createKey(SubjectPublicKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
    }

    public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo keyInfo) throws IOException {
        return createKey(keyInfo, null);
    }

    public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
        AlgorithmIdentifier algID = keyInfo.getAlgorithm();
        SubjectPublicKeyInfoConverter converter = (SubjectPublicKeyInfoConverter) converters.get(algID.getAlgorithm());
        if (converter != null) {
            return converter.getPublicKeyParameters(keyInfo, defaultParams);
        }
        throw new IOException("algorithm identifier in public key not recognised: " + algID.getAlgorithm());
    }

    /* access modifiers changed from: private */
    public static abstract class SubjectPublicKeyInfoConverter {
        /* access modifiers changed from: package-private */
        public abstract AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo subjectPublicKeyInfo, Object obj) throws IOException;

        private SubjectPublicKeyInfoConverter() {
        }
    }

    private static class RSAConverter extends SubjectPublicKeyInfoConverter {
        private RSAConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            RSAPublicKey pubKey = RSAPublicKey.getInstance(keyInfo.parsePublicKey());
            return new RSAKeyParameters(false, pubKey.getModulus(), pubKey.getPublicExponent());
        }
    }

    private static class DHPublicNumberConverter extends SubjectPublicKeyInfoConverter {
        private DHPublicNumberConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            BigInteger y = DHPublicKey.getInstance(keyInfo.parsePublicKey()).getY();
            DomainParameters dhParams = DomainParameters.getInstance(keyInfo.getAlgorithm().getParameters());
            BigInteger p = dhParams.getP();
            BigInteger g = dhParams.getG();
            BigInteger q = dhParams.getQ();
            BigInteger j = null;
            if (dhParams.getJ() != null) {
                j = dhParams.getJ();
            }
            DHValidationParameters validation = null;
            ValidationParams dhValidationParms = dhParams.getValidationParams();
            if (dhValidationParms != null) {
                validation = new DHValidationParameters(dhValidationParms.getSeed(), dhValidationParms.getPgenCounter().intValue());
            }
            return new DHPublicKeyParameters(y, new DHParameters(p, g, q, j, validation));
        }
    }

    private static class DHAgreementConverter extends SubjectPublicKeyInfoConverter {
        private DHAgreementConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            DHParameter params = DHParameter.getInstance(keyInfo.getAlgorithm().getParameters());
            ASN1Integer derY = (ASN1Integer) keyInfo.parsePublicKey();
            BigInteger lVal = params.getL();
            return new DHPublicKeyParameters(derY.getValue(), new DHParameters(params.getP(), params.getG(), null, lVal == null ? 0 : lVal.intValue()));
        }
    }

    private static class ElGamalConverter extends SubjectPublicKeyInfoConverter {
        private ElGamalConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            ElGamalParameter params = ElGamalParameter.getInstance(keyInfo.getAlgorithm().getParameters());
            return new ElGamalPublicKeyParameters(((ASN1Integer) keyInfo.parsePublicKey()).getValue(), new ElGamalParameters(params.getP(), params.getG()));
        }
    }

    private static class DSAConverter extends SubjectPublicKeyInfoConverter {
        private DSAConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            ASN1Integer derY = (ASN1Integer) keyInfo.parsePublicKey();
            ASN1Encodable de = keyInfo.getAlgorithm().getParameters();
            DSAParameters parameters = null;
            if (de != null) {
                DSAParameter params = DSAParameter.getInstance(de.toASN1Primitive());
                parameters = new DSAParameters(params.getP(), params.getQ(), params.getG());
            }
            return new DSAPublicKeyParameters(derY.getValue(), parameters);
        }
    }

    private static class ECConverter extends SubjectPublicKeyInfoConverter {
        private ECConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) {
            ECDomainParameters dParams;
            X962Parameters params = X962Parameters.getInstance(keyInfo.getAlgorithm().getParameters());
            if (params.isNamedCurve()) {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) params.getParameters();
                X9ECParameters x9 = CustomNamedCurves.getByOID(oid);
                if (x9 == null) {
                    x9 = ECNamedCurveTable.getByOID(oid);
                }
                dParams = new ECNamedDomainParameters(oid, x9);
            } else if (params.isImplicitlyCA()) {
                dParams = (ECDomainParameters) defaultParams;
            } else {
                dParams = new ECDomainParameters(X9ECParameters.getInstance(params.getParameters()));
            }
            byte[] data = keyInfo.getPublicKeyData().getBytes();
            ASN1OctetString key = new DEROctetString(data);
            if (data[0] == 4 && data[1] == data.length - 2 && ((data[2] == 2 || data[2] == 3) && new X9IntegerConverter().getByteLength(dParams.getCurve()) >= data.length - 3)) {
                try {
                    key = (ASN1OctetString) ASN1Primitive.fromByteArray(data);
                } catch (IOException e) {
                    throw new IllegalArgumentException("error recovering public key");
                }
            }
            return new ECPublicKeyParameters(new X9ECPoint(dParams.getCurve(), key).getPoint(), dParams);
        }
    }

    private static class GOST3410_2001Converter extends SubjectPublicKeyInfoConverter {
        private GOST3410_2001Converter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) {
            GOST3410PublicKeyAlgParameters gostParams = GOST3410PublicKeyAlgParameters.getInstance(keyInfo.getAlgorithm().getParameters());
            ASN1ObjectIdentifier publicKeyParamSet = gostParams.getPublicKeyParamSet();
            ECGOST3410Parameters ecDomainParameters = new ECGOST3410Parameters(new ECNamedDomainParameters(publicKeyParamSet, ECGOST3410NamedCurves.getByOIDX9(publicKeyParamSet)), publicKeyParamSet, gostParams.getDigestParamSet(), gostParams.getEncryptionParamSet());
            try {
                int keySize = 32 * 2;
                byte[] keyEnc = ((ASN1OctetString) keyInfo.parsePublicKey()).getOctets();
                if (keyEnc.length != keySize) {
                    throw new IllegalArgumentException("invalid length for GOST3410_2001 public key");
                }
                byte[] x9Encoding = new byte[65];
                x9Encoding[0] = 4;
                for (int i = 1; i <= 32; i++) {
                    x9Encoding[i] = keyEnc[32 - i];
                    x9Encoding[i + 32] = keyEnc[64 - i];
                }
                return new ECPublicKeyParameters(ecDomainParameters.getCurve().decodePoint(x9Encoding), ecDomainParameters);
            } catch (IOException e) {
                throw new IllegalArgumentException("error recovering GOST3410_2001 public key");
            }
        }
    }

    private static class GOST3410_2012Converter extends SubjectPublicKeyInfoConverter {
        private GOST3410_2012Converter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) {
            AlgorithmIdentifier algID = keyInfo.getAlgorithm();
            ASN1ObjectIdentifier algOid = algID.getAlgorithm();
            GOST3410PublicKeyAlgParameters gostParams = GOST3410PublicKeyAlgParameters.getInstance(algID.getParameters());
            ASN1ObjectIdentifier publicKeyParamSet = gostParams.getPublicKeyParamSet();
            ECGOST3410Parameters ecDomainParameters = new ECGOST3410Parameters(new ECNamedDomainParameters(publicKeyParamSet, ECGOST3410NamedCurves.getByOIDX9(publicKeyParamSet)), publicKeyParamSet, gostParams.getDigestParamSet(), gostParams.getEncryptionParamSet());
            try {
                ASN1OctetString key = (ASN1OctetString) keyInfo.parsePublicKey();
                int fieldSize = 32;
                if (algOid.equals((ASN1Primitive) RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512)) {
                    fieldSize = 64;
                }
                int keySize = fieldSize * 2;
                byte[] keyEnc = key.getOctets();
                if (keyEnc.length != keySize) {
                    throw new IllegalArgumentException("invalid length for GOST3410_2012 public key");
                }
                byte[] x9Encoding = new byte[(keySize + 1)];
                x9Encoding[0] = 4;
                for (int i = 1; i <= fieldSize; i++) {
                    x9Encoding[i] = keyEnc[fieldSize - i];
                    x9Encoding[i + fieldSize] = keyEnc[keySize - i];
                }
                return new ECPublicKeyParameters(ecDomainParameters.getCurve().decodePoint(x9Encoding), ecDomainParameters);
            } catch (IOException e) {
                throw new IllegalArgumentException("error recovering GOST3410_2012 public key");
            }
        }
    }

    private static class DSTUConverter extends SubjectPublicKeyInfoConverter {
        private DSTUConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            ECDomainParameters ecDomain;
            AlgorithmIdentifier algID = keyInfo.getAlgorithm();
            ASN1ObjectIdentifier algOid = algID.getAlgorithm();
            DSTU4145Params dstuParams = DSTU4145Params.getInstance(algID.getParameters());
            try {
                byte[] keyEnc = Arrays.clone(((ASN1OctetString) keyInfo.parsePublicKey()).getOctets());
                if (algOid.equals((ASN1Primitive) UAObjectIdentifiers.dstu4145le)) {
                    reverseBytes(keyEnc);
                }
                if (dstuParams.isNamedCurve()) {
                    ecDomain = DSTU4145NamedCurves.getByOID(dstuParams.getNamedCurve());
                } else {
                    DSTU4145ECBinary binary = dstuParams.getECBinary();
                    byte[] b_bytes = binary.getB();
                    if (algOid.equals((ASN1Primitive) UAObjectIdentifiers.dstu4145le)) {
                        reverseBytes(b_bytes);
                    }
                    BigInteger b = new BigInteger(1, b_bytes);
                    DSTU4145BinaryField field = binary.getField();
                    ECCurve curve = new ECCurve.F2m(field.getM(), field.getK1(), field.getK2(), field.getK3(), binary.getA(), b);
                    byte[] g_bytes = binary.getG();
                    if (algOid.equals((ASN1Primitive) UAObjectIdentifiers.dstu4145le)) {
                        reverseBytes(g_bytes);
                    }
                    ecDomain = new ECDomainParameters(curve, DSTU4145PointEncoder.decodePoint(curve, g_bytes), binary.getN());
                }
                return new ECPublicKeyParameters(DSTU4145PointEncoder.decodePoint(ecDomain.getCurve(), keyEnc), ecDomain);
            } catch (IOException e) {
                throw new IllegalArgumentException("error recovering DSTU public key");
            }
        }

        private void reverseBytes(byte[] bytes) {
            for (int i = 0; i < bytes.length / 2; i++) {
                byte tmp = bytes[i];
                bytes[i] = bytes[(bytes.length - 1) - i];
                bytes[(bytes.length - 1) - i] = tmp;
            }
        }
    }

    private static class X25519Converter extends SubjectPublicKeyInfoConverter {
        private X25519Converter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) {
            return new X25519PublicKeyParameters(PublicKeyFactory.getRawKey(keyInfo, defaultParams));
        }
    }

    private static class X448Converter extends SubjectPublicKeyInfoConverter {
        private X448Converter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) {
            return new X448PublicKeyParameters(PublicKeyFactory.getRawKey(keyInfo, defaultParams));
        }
    }

    private static class Ed25519Converter extends SubjectPublicKeyInfoConverter {
        private Ed25519Converter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) {
            return new Ed25519PublicKeyParameters(PublicKeyFactory.getRawKey(keyInfo, defaultParams));
        }
    }

    private static class Ed448Converter extends SubjectPublicKeyInfoConverter {
        private Ed448Converter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) {
            return new Ed448PublicKeyParameters(PublicKeyFactory.getRawKey(keyInfo, defaultParams));
        }
    }

    /* access modifiers changed from: private */
    public static byte[] getRawKey(SubjectPublicKeyInfo keyInfo, Object defaultParams) {
        return keyInfo.getPublicKeyData().getOctets();
    }
}
