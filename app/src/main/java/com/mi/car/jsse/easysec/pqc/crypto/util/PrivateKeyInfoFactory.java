package com.mi.car.jsse.easysec.pqc.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.asn1.CMCEPrivateKey;
import com.mi.car.jsse.easysec.pqc.asn1.CMCEPublicKey;
import com.mi.car.jsse.easysec.pqc.asn1.McElieceCCA2PrivateKey;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.asn1.SPHINCS256KeyParams;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSKeyParams;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSMTKeyParams;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSMTPrivateKey;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSPrivateKey;
import com.mi.car.jsse.easysec.pqc.crypto.cmce.CMCEPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.Composer;
import com.mi.car.jsse.easysec.pqc.crypto.lms.HSSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.newhope.NHPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.BDS;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.BDSStateMap;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSUtil;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.IOException;

public class PrivateKeyInfoFactory {
    private PrivateKeyInfoFactory() {
    }

    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey) throws IOException {
        return createPrivateKeyInfo(privateKey, null);
    }

    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes) throws IOException {
        if (privateKey instanceof QTESLAPrivateKeyParameters) {
            QTESLAPrivateKeyParameters keyParams = (QTESLAPrivateKeyParameters) privateKey;
            return new PrivateKeyInfo(Utils.qTeslaLookupAlgID(keyParams.getSecurityCategory()), new DEROctetString(keyParams.getSecret()), attributes);
        } else if (privateKey instanceof SPHINCSPrivateKeyParameters) {
            SPHINCSPrivateKeyParameters params = (SPHINCSPrivateKeyParameters) privateKey;
            return new PrivateKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256, new SPHINCS256KeyParams(Utils.sphincs256LookupTreeAlgID(params.getTreeDigest()))), new DEROctetString(params.getKeyData()));
        } else if (privateKey instanceof NHPrivateKeyParameters) {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);
            short[] privateKeyData = ((NHPrivateKeyParameters) privateKey).getSecData();
            byte[] octets = new byte[(privateKeyData.length * 2)];
            for (int i = 0; i != privateKeyData.length; i++) {
                Pack.shortToLittleEndian(privateKeyData[i], octets, i * 2);
            }
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(octets));
        } else if (privateKey instanceof LMSPrivateKeyParameters) {
            LMSPrivateKeyParameters params2 = (LMSPrivateKeyParameters) privateKey;
            byte[] encoding = Composer.compose().u32str(1).bytes(params2).build();
            return new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig), new DEROctetString(encoding), attributes, Composer.compose().u32str(1).bytes(params2.getPublicKey()).build());
        } else if (privateKey instanceof HSSPrivateKeyParameters) {
            HSSPrivateKeyParameters params3 = (HSSPrivateKeyParameters) privateKey;
            byte[] encoding2 = Composer.compose().u32str(params3.getL()).bytes(params3).build();
            return new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig), new DEROctetString(encoding2), attributes, Composer.compose().u32str(params3.getL()).bytes(params3.getPublicKey().getLMSPublicKey()).build());
        } else if (privateKey instanceof SPHINCSPlusPrivateKeyParameters) {
            SPHINCSPlusPrivateKeyParameters params4 = (SPHINCSPlusPrivateKeyParameters) privateKey;
            byte[] encoding3 = params4.getEncoded();
            return new PrivateKeyInfo(new AlgorithmIdentifier(Utils.sphincsPlusOidLookup(params4.getParameters())), new DEROctetString(encoding3), attributes, params4.getEncodedPublicKey());
        } else if (privateKey instanceof CMCEPrivateKeyParameters) {
            CMCEPrivateKeyParameters params5 = (CMCEPrivateKeyParameters) privateKey;
            params5.getEncoded();
            return new PrivateKeyInfo(new AlgorithmIdentifier(Utils.mcElieceOidLookup(params5.getParameters())), new CMCEPrivateKey(0, params5.getDelta(), params5.getC(), params5.getG(), params5.getAlpha(), params5.getS(), new CMCEPublicKey(params5.reconstructPublicKey())), attributes);
        } else if (privateKey instanceof XMSSPrivateKeyParameters) {
            XMSSPrivateKeyParameters keyParams2 = (XMSSPrivateKeyParameters) privateKey;
            return new PrivateKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.xmss, new XMSSKeyParams(keyParams2.getParameters().getHeight(), Utils.xmssLookupTreeAlgID(keyParams2.getTreeDigest()))), xmssCreateKeyStructure(keyParams2), attributes);
        } else if (privateKey instanceof XMSSMTPrivateKeyParameters) {
            XMSSMTPrivateKeyParameters keyParams3 = (XMSSMTPrivateKeyParameters) privateKey;
            return new PrivateKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt, new XMSSMTKeyParams(keyParams3.getParameters().getHeight(), keyParams3.getParameters().getLayers(), Utils.xmssLookupTreeAlgID(keyParams3.getTreeDigest()))), xmssmtCreateKeyStructure(keyParams3), attributes);
        } else if (privateKey instanceof McElieceCCA2PrivateKeyParameters) {
            McElieceCCA2PrivateKeyParameters priv = (McElieceCCA2PrivateKeyParameters) privateKey;
            return new PrivateKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.mcElieceCca2), new McElieceCCA2PrivateKey(priv.getN(), priv.getK(), priv.getField(), priv.getGoppaPoly(), priv.getP(), Utils.getAlgorithmIdentifier(priv.getDigest())));
        } else if (privateKey instanceof FrodoPrivateKeyParameters) {
            FrodoPrivateKeyParameters params6 = (FrodoPrivateKeyParameters) privateKey;
            return new PrivateKeyInfo(new AlgorithmIdentifier(Utils.frodoOidLookup(params6.getParameters())), new DEROctetString(params6.getEncoded()), attributes);
        } else if (privateKey instanceof SABERPrivateKeyParameters) {
            SABERPrivateKeyParameters params7 = (SABERPrivateKeyParameters) privateKey;
            return new PrivateKeyInfo(new AlgorithmIdentifier(Utils.saberOidLookup(params7.getParameters())), new DEROctetString(params7.getEncoded()), attributes);
        } else {
            throw new IOException("key parameters not recognized");
        }
    }

    private static XMSSPrivateKey xmssCreateKeyStructure(XMSSPrivateKeyParameters keyParams) throws IOException {
        byte[] keyData = keyParams.getEncoded();
        int n = keyParams.getParameters().getTreeDigestSize();
        int totalHeight = keyParams.getParameters().getHeight();
        int index = (int) XMSSUtil.bytesToXBigEndian(keyData, 0, 4);
        if (!XMSSUtil.isIndexValid(totalHeight, (long) index)) {
            throw new IllegalArgumentException("index out of bounds");
        }
        byte[] secretKeySeed = XMSSUtil.extractBytesAtOffset(keyData, 0 + 4, n);
        int position = n + 4;
        byte[] secretKeyPRF = XMSSUtil.extractBytesAtOffset(keyData, position, n);
        int position2 = position + n;
        byte[] publicSeed = XMSSUtil.extractBytesAtOffset(keyData, position2, n);
        int position3 = position2 + n;
        byte[] root = XMSSUtil.extractBytesAtOffset(keyData, position3, n);
        int position4 = position3 + n;
        byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(keyData, position4, keyData.length - position4);
        try {
            BDS bds = (BDS) XMSSUtil.deserialize(bdsStateBinary, BDS.class);
            if (bds.getMaxIndex() != (1 << totalHeight) - 1) {
                return new XMSSPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary, bds.getMaxIndex());
            }
            return new XMSSPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
        } catch (ClassNotFoundException e) {
            throw new IOException("cannot parse BDS: " + e.getMessage());
        }
    }

    private static XMSSMTPrivateKey xmssmtCreateKeyStructure(XMSSMTPrivateKeyParameters keyParams) throws IOException {
        byte[] keyData = keyParams.getEncoded();
        int n = keyParams.getParameters().getTreeDigestSize();
        int totalHeight = keyParams.getParameters().getHeight();
        int indexSize = (totalHeight + 7) / 8;
        int index = (int) XMSSUtil.bytesToXBigEndian(keyData, 0, indexSize);
        if (!XMSSUtil.isIndexValid(totalHeight, (long) index)) {
            throw new IllegalArgumentException("index out of bounds");
        }
        int position = 0 + indexSize;
        byte[] secretKeySeed = XMSSUtil.extractBytesAtOffset(keyData, position, n);
        int position2 = position + n;
        byte[] secretKeyPRF = XMSSUtil.extractBytesAtOffset(keyData, position2, n);
        int position3 = position2 + n;
        byte[] publicSeed = XMSSUtil.extractBytesAtOffset(keyData, position3, n);
        int position4 = position3 + n;
        byte[] root = XMSSUtil.extractBytesAtOffset(keyData, position4, n);
        int position5 = position4 + n;
        byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(keyData, position5, keyData.length - position5);
        try {
            BDSStateMap bds = (BDSStateMap) XMSSUtil.deserialize(bdsStateBinary, BDSStateMap.class);
            if (bds.getMaxIndex() != (1 << totalHeight) - 1) {
                return new XMSSMTPrivateKey((long) index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary, bds.getMaxIndex());
            }
            return new XMSSMTPrivateKey((long) index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
        } catch (ClassNotFoundException e) {
            throw new IOException("cannot parse BDSStateMap: " + e.getMessage());
        }
    }
}
