package com.mi.car.jsse.easysec.pqc.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1InputStream;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.bc.BCObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.asn1.CMCEPrivateKey;
import com.mi.car.jsse.easysec.pqc.asn1.McElieceCCA2PrivateKey;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.asn1.SPHINCS256KeyParams;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSKeyParams;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSMTKeyParams;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSMTPrivateKey;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSPrivateKey;
import com.mi.car.jsse.easysec.pqc.crypto.cmce.CMCEPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.HSSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.newhope.NHPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.BDS;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.BDSStateMap;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSUtil;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.IOException;
import java.io.InputStream;

public class PrivateKeyFactory {
    public static AsymmetricKeyParameter createKey(byte[] privateKeyInfoData) throws IOException {
        return createKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privateKeyInfoData)));
    }

    public static AsymmetricKeyParameter createKey(InputStream inStr) throws IOException {
        return createKey(PrivateKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
    }

    public static AsymmetricKeyParameter createKey(PrivateKeyInfo keyInfo) throws IOException {
        ASN1ObjectIdentifier algOID = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();
        if (algOID.on(BCObjectIdentifiers.qTESLA)) {
            return new QTESLAPrivateKeyParameters(Utils.qTeslaLookupSecurityCategory(keyInfo.getPrivateKeyAlgorithm()), ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets());
        } else if (algOID.equals((ASN1Primitive) BCObjectIdentifiers.sphincs256)) {
            return new SPHINCSPrivateKeyParameters(ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets(), Utils.sphincs256LookupTreeAlgName(SPHINCS256KeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters())));
        } else {
            if (algOID.equals((ASN1Primitive) BCObjectIdentifiers.newHope)) {
                return new NHPrivateKeyParameters(convert(ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets()));
            }
            if (algOID.equals((ASN1Primitive) PKCSObjectIdentifiers.id_alg_hss_lms_hashsig)) {
                byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
                ASN1BitString pubKey = keyInfo.getPublicKeyData();
                if (Pack.bigEndianToInt(keyEnc, 0) == 1) {
                    if (pubKey == null) {
                        return LMSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
                    }
                    byte[] pubEnc = pubKey.getOctets();
                    return LMSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length), Arrays.copyOfRange(pubEnc, 4, pubEnc.length));
                } else if (pubKey == null) {
                    return HSSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
                } else {
                    return HSSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length), pubKey.getOctets());
                }
            } else if (algOID.on(BCObjectIdentifiers.sphincsPlus)) {
                byte[] keyEnc2 = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
                return new SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters.getParams(Integers.valueOf(Pack.bigEndianToInt(keyEnc2, 0))), Arrays.copyOfRange(keyEnc2, 4, keyEnc2.length));
            } else if (algOID.on(BCObjectIdentifiers.pqc_kem_mceliece)) {
                CMCEPrivateKey cmceKey = CMCEPrivateKey.getInstance(keyInfo.parsePrivateKey());
                return new CMCEPrivateKeyParameters(Utils.mcElieceParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()), cmceKey.getDelta(), cmceKey.getC(), cmceKey.getG(), cmceKey.getAlpha(), cmceKey.getS());
            } else if (algOID.on(BCObjectIdentifiers.pqc_kem_frodo)) {
                return new FrodoPrivateKeyParameters(Utils.frodoParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()), ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets());
            } else if (algOID.on(BCObjectIdentifiers.pqc_kem_saber)) {
                return new SABERPrivateKeyParameters(Utils.saberParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()), ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets());
            } else if (algOID.equals((ASN1Primitive) BCObjectIdentifiers.xmss)) {
                XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
                ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();
                XMSSPrivateKey xmssPrivateKey = XMSSPrivateKey.getInstance(keyInfo.parsePrivateKey());
                try {
                    XMSSPrivateKeyParameters.Builder keyBuilder = new XMSSPrivateKeyParameters.Builder(new XMSSParameters(keyParams.getHeight(), Utils.getDigest(treeDigest))).withIndex(xmssPrivateKey.getIndex()).withSecretKeySeed(xmssPrivateKey.getSecretKeySeed()).withSecretKeyPRF(xmssPrivateKey.getSecretKeyPRF()).withPublicSeed(xmssPrivateKey.getPublicSeed()).withRoot(xmssPrivateKey.getRoot());
                    if (xmssPrivateKey.getVersion() != 0) {
                        keyBuilder.withMaxIndex(xmssPrivateKey.getMaxIndex());
                    }
                    if (xmssPrivateKey.getBdsState() != null) {
                        keyBuilder.withBDSState(((BDS) XMSSUtil.deserialize(xmssPrivateKey.getBdsState(), BDS.class)).withWOTSDigest(treeDigest));
                    }
                    return keyBuilder.build();
                } catch (ClassNotFoundException e) {
                    throw new IOException("ClassNotFoundException processing BDS state: " + e.getMessage());
                }
            } else if (algOID.equals((ASN1Primitive) PQCObjectIdentifiers.xmss_mt)) {
                XMSSMTKeyParams keyParams2 = XMSSMTKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
                ASN1ObjectIdentifier treeDigest2 = keyParams2.getTreeDigest().getAlgorithm();
                try {
                    XMSSMTPrivateKey xmssMtPrivateKey = XMSSMTPrivateKey.getInstance(keyInfo.parsePrivateKey());
                    XMSSMTPrivateKeyParameters.Builder keyBuilder2 = new XMSSMTPrivateKeyParameters.Builder(new XMSSMTParameters(keyParams2.getHeight(), keyParams2.getLayers(), Utils.getDigest(treeDigest2))).withIndex(xmssMtPrivateKey.getIndex()).withSecretKeySeed(xmssMtPrivateKey.getSecretKeySeed()).withSecretKeyPRF(xmssMtPrivateKey.getSecretKeyPRF()).withPublicSeed(xmssMtPrivateKey.getPublicSeed()).withRoot(xmssMtPrivateKey.getRoot());
                    if (xmssMtPrivateKey.getVersion() != 0) {
                        keyBuilder2.withMaxIndex(xmssMtPrivateKey.getMaxIndex());
                    }
                    if (xmssMtPrivateKey.getBdsState() != null) {
                        keyBuilder2.withBDSState(((BDSStateMap) XMSSUtil.deserialize(xmssMtPrivateKey.getBdsState(), BDSStateMap.class)).withWOTSDigest(treeDigest2));
                    }
                    return keyBuilder2.build();
                } catch (ClassNotFoundException e2) {
                    throw new IOException("ClassNotFoundException processing BDS state: " + e2.getMessage());
                }
            } else if (algOID.equals((ASN1Primitive) PQCObjectIdentifiers.mcElieceCca2)) {
                McElieceCCA2PrivateKey mKey = McElieceCCA2PrivateKey.getInstance(keyInfo.parsePrivateKey());
                return new McElieceCCA2PrivateKeyParameters(mKey.getN(), mKey.getK(), mKey.getField(), mKey.getGoppaPoly(), mKey.getP(), Utils.getDigestName(mKey.getDigest().getAlgorithm()));
            } else {
                throw new RuntimeException("algorithm identifier in private key not recognised");
            }
        }
    }

    private static short[] convert(byte[] octets) {
        short[] rv = new short[(octets.length / 2)];
        for (int i = 0; i != rv.length; i++) {
            rv[i] = Pack.littleEndianToShort(octets, i * 2);
        }
        return rv;
    }
}
