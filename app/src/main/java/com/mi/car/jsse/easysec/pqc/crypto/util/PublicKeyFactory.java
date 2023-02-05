package com.mi.car.jsse.easysec.pqc.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1InputStream;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.bc.BCObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.isara.IsaraObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.asn1.CMCEPublicKey;
import com.mi.car.jsse.easysec.pqc.asn1.McElieceCCA2PublicKey;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.asn1.SPHINCS256KeyParams;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSKeyParams;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSMTKeyParams;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSPublicKey;
import com.mi.car.jsse.easysec.pqc.crypto.cmce.CMCEPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.HSSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.newhope.NHPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPublicKeyParameters;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

public class PublicKeyFactory {
    private static Map converters = new HashMap();

    static {
        converters.put(PQCObjectIdentifiers.qTESLA_p_I, new QTeslaConverter());
        converters.put(PQCObjectIdentifiers.qTESLA_p_III, new QTeslaConverter());
        converters.put(PQCObjectIdentifiers.sphincs256, new SPHINCSConverter());
        converters.put(PQCObjectIdentifiers.newHope, new NHConverter());
        converters.put(PQCObjectIdentifiers.xmss, new XMSSConverter());
        converters.put(PQCObjectIdentifiers.xmss_mt, new XMSSMTConverter());
        converters.put(IsaraObjectIdentifiers.id_alg_xmss, new XMSSConverter());
        converters.put(IsaraObjectIdentifiers.id_alg_xmssmt, new XMSSMTConverter());
        converters.put(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, new LMSConverter());
        converters.put(PQCObjectIdentifiers.mcElieceCca2, new McElieceCCA2Converter());
        converters.put(BCObjectIdentifiers.sphincsPlus, new SPHINCSPlusConverter());
        converters.put(BCObjectIdentifiers.sphincsPlus_shake_256, new SPHINCSPlusConverter());
        converters.put(BCObjectIdentifiers.sphincsPlus_sha_256, new SPHINCSPlusConverter());
        converters.put(BCObjectIdentifiers.sphincsPlus_sha_512, new SPHINCSPlusConverter());
        converters.put(BCObjectIdentifiers.mceliece348864_r3, new CMCEConverter());
        converters.put(BCObjectIdentifiers.mceliece348864f_r3, new CMCEConverter());
        converters.put(BCObjectIdentifiers.mceliece460896_r3, new CMCEConverter());
        converters.put(BCObjectIdentifiers.mceliece460896f_r3, new CMCEConverter());
        converters.put(BCObjectIdentifiers.mceliece6688128_r3, new CMCEConverter());
        converters.put(BCObjectIdentifiers.mceliece6688128f_r3, new CMCEConverter());
        converters.put(BCObjectIdentifiers.mceliece6960119_r3, new CMCEConverter());
        converters.put(BCObjectIdentifiers.mceliece6960119f_r3, new CMCEConverter());
        converters.put(BCObjectIdentifiers.mceliece8192128_r3, new CMCEConverter());
        converters.put(BCObjectIdentifiers.mceliece8192128f_r3, new CMCEConverter());
        converters.put(BCObjectIdentifiers.frodokem19888r3, new FrodoConverter());
        converters.put(BCObjectIdentifiers.frodokem19888shaker3, new FrodoConverter());
        converters.put(BCObjectIdentifiers.frodokem31296r3, new FrodoConverter());
        converters.put(BCObjectIdentifiers.frodokem31296shaker3, new FrodoConverter());
        converters.put(BCObjectIdentifiers.frodokem43088r3, new FrodoConverter());
        converters.put(BCObjectIdentifiers.frodokem43088shaker3, new FrodoConverter());
        converters.put(BCObjectIdentifiers.lightsaberkem128r3, new SABERConverter());
        converters.put(BCObjectIdentifiers.saberkem128r3, new SABERConverter());
        converters.put(BCObjectIdentifiers.firesaberkem128r3, new SABERConverter());
        converters.put(BCObjectIdentifiers.lightsaberkem192r3, new SABERConverter());
        converters.put(BCObjectIdentifiers.saberkem192r3, new SABERConverter());
        converters.put(BCObjectIdentifiers.firesaberkem192r3, new SABERConverter());
        converters.put(BCObjectIdentifiers.lightsaberkem256r3, new SABERConverter());
        converters.put(BCObjectIdentifiers.saberkem256r3, new SABERConverter());
        converters.put(BCObjectIdentifiers.firesaberkem256r3, new SABERConverter());
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
        AlgorithmIdentifier algId = keyInfo.getAlgorithm();
        SubjectPublicKeyInfoConverter converter = (SubjectPublicKeyInfoConverter) converters.get(algId.getAlgorithm());
        if (converter != null) {
            return converter.getPublicKeyParameters(keyInfo, defaultParams);
        }
        throw new IOException("algorithm identifier in public key not recognised: " + algId.getAlgorithm());
    }

    /* access modifiers changed from: private */
    public static abstract class SubjectPublicKeyInfoConverter {
        /* access modifiers changed from: package-private */
        public abstract AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo subjectPublicKeyInfo, Object obj) throws IOException;

        private SubjectPublicKeyInfoConverter() {
        }
    }

    private static class QTeslaConverter extends SubjectPublicKeyInfoConverter {
        private QTeslaConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            return new QTESLAPublicKeyParameters(Utils.qTeslaLookupSecurityCategory(keyInfo.getAlgorithm()), keyInfo.getPublicKeyData().getOctets());
        }
    }

    private static class SPHINCSConverter extends SubjectPublicKeyInfoConverter {
        private SPHINCSConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            return new SPHINCSPublicKeyParameters(keyInfo.getPublicKeyData().getBytes(), Utils.sphincs256LookupTreeAlgName(SPHINCS256KeyParams.getInstance(keyInfo.getAlgorithm().getParameters())));
        }
    }

    private static class NHConverter extends SubjectPublicKeyInfoConverter {
        private NHConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            return new NHPublicKeyParameters(keyInfo.getPublicKeyData().getBytes());
        }
    }

    private static class XMSSConverter extends SubjectPublicKeyInfoConverter {
        private XMSSConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getAlgorithm().getParameters());
            if (keyParams != null) {
                ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();
                XMSSPublicKey xmssPublicKey = XMSSPublicKey.getInstance(keyInfo.parsePublicKey());
                return new XMSSPublicKeyParameters.Builder(new XMSSParameters(keyParams.getHeight(), Utils.getDigest(treeDigest))).withPublicSeed(xmssPublicKey.getPublicSeed()).withRoot(xmssPublicKey.getRoot()).build();
            }
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();
            return new XMSSPublicKeyParameters.Builder(XMSSParameters.lookupByOID(Pack.bigEndianToInt(keyEnc, 0))).withPublicKey(keyEnc).build();
        }
    }

    private static class XMSSMTConverter extends SubjectPublicKeyInfoConverter {
        private XMSSMTConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getAlgorithm().getParameters());
            if (keyParams != null) {
                ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();
                XMSSPublicKey xmssMtPublicKey = XMSSPublicKey.getInstance(keyInfo.parsePublicKey());
                return new XMSSMTPublicKeyParameters.Builder(new XMSSMTParameters(keyParams.getHeight(), keyParams.getLayers(), Utils.getDigest(treeDigest))).withPublicSeed(xmssMtPublicKey.getPublicSeed()).withRoot(xmssMtPublicKey.getRoot()).build();
            }
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();
            return new XMSSMTPublicKeyParameters.Builder(XMSSMTParameters.lookupByOID(Pack.bigEndianToInt(keyEnc, 0))).withPublicKey(keyEnc).build();
        }
    }

    private static class LMSConverter extends SubjectPublicKeyInfoConverter {
        private LMSConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();
            if (Pack.bigEndianToInt(keyEnc, 0) == 1) {
                return LMSPublicKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
            }
            if (keyEnc.length == 64) {
                keyEnc = Arrays.copyOfRange(keyEnc, 4, keyEnc.length);
            }
            return HSSPublicKeyParameters.getInstance(keyEnc);
        }
    }

    private static class SPHINCSPlusConverter extends SubjectPublicKeyInfoConverter {
        private SPHINCSPlusConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();
            return new SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters.getParams(Integers.valueOf(Pack.bigEndianToInt(keyEnc, 0))), Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
        }
    }

    private static class CMCEConverter extends SubjectPublicKeyInfoConverter {
        private CMCEConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            return new CMCEPublicKeyParameters(Utils.mcElieceParamsLookup(keyInfo.getAlgorithm().getAlgorithm()), CMCEPublicKey.getInstance(keyInfo.parsePublicKey()).getT());
        }
    }

    private static class SABERConverter extends SubjectPublicKeyInfoConverter {
        private SABERConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            return new SABERPublicKeyParameters(Utils.saberParamsLookup(keyInfo.getAlgorithm().getAlgorithm()), ASN1OctetString.getInstance(ASN1Sequence.getInstance(keyInfo.parsePublicKey()).getObjectAt(0)).getOctets());
        }
    }

    private static class McElieceCCA2Converter extends SubjectPublicKeyInfoConverter {
        private McElieceCCA2Converter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            McElieceCCA2PublicKey mKey = McElieceCCA2PublicKey.getInstance(keyInfo.parsePublicKey());
            return new McElieceCCA2PublicKeyParameters(mKey.getN(), mKey.getT(), mKey.getG(), Utils.getDigestName(mKey.getDigest().getAlgorithm()));
        }
    }

    private static class FrodoConverter extends SubjectPublicKeyInfoConverter {
        private FrodoConverter() {
            super();
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory.SubjectPublicKeyInfoConverter
        public AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
            return new FrodoPublicKeyParameters(Utils.frodoParamsLookup(keyInfo.getAlgorithm().getAlgorithm()), ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets());
        }
    }
}
