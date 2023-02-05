package com.mi.car.jsse.easysec.pqc.crypto.util;

import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
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
import com.mi.car.jsse.easysec.pqc.asn1.XMSSMTPublicKey;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSPublicKey;
import com.mi.car.jsse.easysec.pqc.crypto.cmce.CMCEPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.Composer;
import com.mi.car.jsse.easysec.pqc.crypto.lms.HSSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.newhope.NHPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPublicKeyParameters;
import java.io.IOException;

public class SubjectPublicKeyInfoFactory {
    private SubjectPublicKeyInfoFactory() {
    }

    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) throws IOException {
        if (publicKey instanceof QTESLAPublicKeyParameters) {
            QTESLAPublicKeyParameters keyParams = (QTESLAPublicKeyParameters) publicKey;
            return new SubjectPublicKeyInfo(Utils.qTeslaLookupAlgID(keyParams.getSecurityCategory()), keyParams.getPublicData());
        } else if (publicKey instanceof SPHINCSPublicKeyParameters) {
            SPHINCSPublicKeyParameters params = (SPHINCSPublicKeyParameters) publicKey;
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256, new SPHINCS256KeyParams(Utils.sphincs256LookupTreeAlgID(params.getTreeDigest()))), params.getKeyData());
        } else if (publicKey instanceof NHPublicKeyParameters) {
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.newHope), ((NHPublicKeyParameters) publicKey).getPubData());
        } else {
            if (publicKey instanceof LMSPublicKeyParameters) {
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig), new DEROctetString(Composer.compose().u32str(1).bytes((LMSPublicKeyParameters) publicKey).build()));
            } else if (publicKey instanceof HSSPublicKeyParameters) {
                HSSPublicKeyParameters params2 = (HSSPublicKeyParameters) publicKey;
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig), new DEROctetString(Composer.compose().u32str(params2.getL()).bytes(params2.getLMSPublicKey()).build()));
            } else if (publicKey instanceof SPHINCSPlusPublicKeyParameters) {
                SPHINCSPlusPublicKeyParameters params3 = (SPHINCSPlusPublicKeyParameters) publicKey;
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(Utils.sphincsPlusOidLookup(params3.getParameters())), new DEROctetString(params3.getEncoded()));
            } else if (publicKey instanceof CMCEPublicKeyParameters) {
                CMCEPublicKeyParameters params4 = (CMCEPublicKeyParameters) publicKey;
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(Utils.mcElieceOidLookup(params4.getParameters())), new CMCEPublicKey(params4.getEncoded()));
            } else if (publicKey instanceof XMSSPublicKeyParameters) {
                XMSSPublicKeyParameters keyParams2 = (XMSSPublicKeyParameters) publicKey;
                byte[] publicSeed = keyParams2.getPublicSeed();
                byte[] root = keyParams2.getRoot();
                byte[] keyEnc = keyParams2.getEncoded();
                if (keyEnc.length > publicSeed.length + root.length) {
                    return new SubjectPublicKeyInfo(new AlgorithmIdentifier(IsaraObjectIdentifiers.id_alg_xmss), new DEROctetString(keyEnc));
                }
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.xmss, new XMSSKeyParams(keyParams2.getParameters().getHeight(), Utils.xmssLookupTreeAlgID(keyParams2.getTreeDigest()))), new XMSSPublicKey(publicSeed, root));
            } else if (publicKey instanceof XMSSMTPublicKeyParameters) {
                XMSSMTPublicKeyParameters keyParams3 = (XMSSMTPublicKeyParameters) publicKey;
                byte[] publicSeed2 = keyParams3.getPublicSeed();
                byte[] root2 = keyParams3.getRoot();
                byte[] keyEnc2 = keyParams3.getEncoded();
                if (keyEnc2.length > publicSeed2.length + root2.length) {
                    return new SubjectPublicKeyInfo(new AlgorithmIdentifier(IsaraObjectIdentifiers.id_alg_xmssmt), new DEROctetString(keyEnc2));
                }
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt, new XMSSMTKeyParams(keyParams3.getParameters().getHeight(), keyParams3.getParameters().getLayers(), Utils.xmssLookupTreeAlgID(keyParams3.getTreeDigest()))), new XMSSMTPublicKey(keyParams3.getPublicSeed(), keyParams3.getRoot()));
            } else if (publicKey instanceof McElieceCCA2PublicKeyParameters) {
                McElieceCCA2PublicKeyParameters pub = (McElieceCCA2PublicKeyParameters) publicKey;
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.mcElieceCca2), new McElieceCCA2PublicKey(pub.getN(), pub.getT(), pub.getG(), Utils.getAlgorithmIdentifier(pub.getDigest())));
            } else if (publicKey instanceof FrodoPublicKeyParameters) {
                FrodoPublicKeyParameters params5 = (FrodoPublicKeyParameters) publicKey;
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(Utils.frodoOidLookup(params5.getParameters())), new DEROctetString(params5.getEncoded()));
            } else if (publicKey instanceof SABERPublicKeyParameters) {
                SABERPublicKeyParameters params6 = (SABERPublicKeyParameters) publicKey;
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(Utils.saberOidLookup(params6.getParameters())), new DERSequence(new DEROctetString(params6.getEncoded())));
            } else {
                throw new IOException("key parameters not recognized");
            }
        }
    }
}
