package com.mi.car.jsse.easysec.pqc.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.bc.BCObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.asn1.SPHINCS256KeyParams;
import com.mi.car.jsse.easysec.pqc.crypto.cmce.CMCEParameters;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoParameters;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import com.mi.car.jsse.easysec.util.Integers;
import java.util.HashMap;
import java.util.Map;

class Utils {
    static final AlgorithmIdentifier AlgID_qTESLA_p_I = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_p_I);
    static final AlgorithmIdentifier AlgID_qTESLA_p_III = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_p_III);
    static final AlgorithmIdentifier SPHINCS_SHA3_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_256);
    static final AlgorithmIdentifier SPHINCS_SHA512_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_256);
    static final AlgorithmIdentifier XMSS_SHA256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    static final AlgorithmIdentifier XMSS_SHA512 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
    static final AlgorithmIdentifier XMSS_SHAKE128 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake128);
    static final AlgorithmIdentifier XMSS_SHAKE256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256);
    static final Map categories = new HashMap();
    static final Map frodoOids = new HashMap();
    static final Map frodoParams = new HashMap();
    static final Map mcElieceOids = new HashMap();
    static final Map mcElieceParams = new HashMap();
    static final Map saberOids = new HashMap();
    static final Map saberParams = new HashMap();
    static final Map sphincsPlusOids = new HashMap();
    static final Map sphincsPlusParams = new HashMap();

    Utils() {
    }

    static {
        categories.put(PQCObjectIdentifiers.qTESLA_p_I, Integers.valueOf(5));
        categories.put(PQCObjectIdentifiers.qTESLA_p_III, Integers.valueOf(6));
        mcElieceOids.put(CMCEParameters.mceliece348864r3, BCObjectIdentifiers.mceliece348864_r3);
        mcElieceOids.put(CMCEParameters.mceliece348864fr3, BCObjectIdentifiers.mceliece348864f_r3);
        mcElieceOids.put(CMCEParameters.mceliece460896r3, BCObjectIdentifiers.mceliece460896_r3);
        mcElieceOids.put(CMCEParameters.mceliece460896fr3, BCObjectIdentifiers.mceliece460896f_r3);
        mcElieceOids.put(CMCEParameters.mceliece6688128r3, BCObjectIdentifiers.mceliece6688128_r3);
        mcElieceOids.put(CMCEParameters.mceliece6688128fr3, BCObjectIdentifiers.mceliece6688128f_r3);
        mcElieceOids.put(CMCEParameters.mceliece6960119r3, BCObjectIdentifiers.mceliece6960119_r3);
        mcElieceOids.put(CMCEParameters.mceliece6960119fr3, BCObjectIdentifiers.mceliece6960119f_r3);
        mcElieceOids.put(CMCEParameters.mceliece8192128r3, BCObjectIdentifiers.mceliece8192128_r3);
        mcElieceOids.put(CMCEParameters.mceliece8192128fr3, BCObjectIdentifiers.mceliece8192128f_r3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece348864_r3, CMCEParameters.mceliece348864r3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece348864f_r3, CMCEParameters.mceliece348864fr3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece460896_r3, CMCEParameters.mceliece460896r3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece460896f_r3, CMCEParameters.mceliece460896fr3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece6688128_r3, CMCEParameters.mceliece6688128r3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece6688128f_r3, CMCEParameters.mceliece6688128fr3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece6960119_r3, CMCEParameters.mceliece6960119r3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece6960119f_r3, CMCEParameters.mceliece6960119fr3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece8192128_r3, CMCEParameters.mceliece8192128r3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece8192128f_r3, CMCEParameters.mceliece8192128fr3);
        frodoOids.put(FrodoParameters.frodokem19888r3, BCObjectIdentifiers.frodokem19888r3);
        frodoOids.put(FrodoParameters.frodokem19888shaker3, BCObjectIdentifiers.frodokem19888shaker3);
        frodoOids.put(FrodoParameters.frodokem31296r3, BCObjectIdentifiers.frodokem31296r3);
        frodoOids.put(FrodoParameters.frodokem31296shaker3, BCObjectIdentifiers.frodokem31296shaker3);
        frodoOids.put(FrodoParameters.frodokem43088r3, BCObjectIdentifiers.frodokem43088r3);
        frodoOids.put(FrodoParameters.frodokem43088shaker3, BCObjectIdentifiers.frodokem43088shaker3);
        frodoParams.put(BCObjectIdentifiers.frodokem19888r3, FrodoParameters.frodokem19888r3);
        frodoParams.put(BCObjectIdentifiers.frodokem19888shaker3, FrodoParameters.frodokem19888shaker3);
        frodoParams.put(BCObjectIdentifiers.frodokem31296r3, FrodoParameters.frodokem31296r3);
        frodoParams.put(BCObjectIdentifiers.frodokem31296shaker3, FrodoParameters.frodokem31296shaker3);
        frodoParams.put(BCObjectIdentifiers.frodokem43088r3, FrodoParameters.frodokem43088r3);
        frodoParams.put(BCObjectIdentifiers.frodokem43088shaker3, FrodoParameters.frodokem43088shaker3);
        saberOids.put(SABERParameters.lightsaberkem128r3, BCObjectIdentifiers.lightsaberkem128r3);
        saberOids.put(SABERParameters.saberkem128r3, BCObjectIdentifiers.saberkem128r3);
        saberOids.put(SABERParameters.firesaberkem128r3, BCObjectIdentifiers.firesaberkem128r3);
        saberOids.put(SABERParameters.lightsaberkem192r3, BCObjectIdentifiers.lightsaberkem192r3);
        saberOids.put(SABERParameters.saberkem192r3, BCObjectIdentifiers.saberkem192r3);
        saberOids.put(SABERParameters.firesaberkem192r3, BCObjectIdentifiers.firesaberkem192r3);
        saberOids.put(SABERParameters.lightsaberkem256r3, BCObjectIdentifiers.lightsaberkem256r3);
        saberOids.put(SABERParameters.saberkem256r3, BCObjectIdentifiers.saberkem256r3);
        saberOids.put(SABERParameters.firesaberkem256r3, BCObjectIdentifiers.firesaberkem256r3);
        saberParams.put(BCObjectIdentifiers.lightsaberkem128r3, SABERParameters.lightsaberkem128r3);
        saberParams.put(BCObjectIdentifiers.saberkem128r3, SABERParameters.saberkem128r3);
        saberParams.put(BCObjectIdentifiers.firesaberkem128r3, SABERParameters.firesaberkem128r3);
        saberParams.put(BCObjectIdentifiers.lightsaberkem192r3, SABERParameters.lightsaberkem192r3);
        saberParams.put(BCObjectIdentifiers.saberkem192r3, SABERParameters.saberkem192r3);
        saberParams.put(BCObjectIdentifiers.firesaberkem192r3, SABERParameters.firesaberkem192r3);
        saberParams.put(BCObjectIdentifiers.lightsaberkem256r3, SABERParameters.lightsaberkem256r3);
        saberParams.put(BCObjectIdentifiers.saberkem256r3, SABERParameters.saberkem256r3);
        saberParams.put(BCObjectIdentifiers.firesaberkem256r3, SABERParameters.firesaberkem256r3);
    }

    static int qTeslaLookupSecurityCategory(AlgorithmIdentifier algorithm) {
        return ((Integer) categories.get(algorithm.getAlgorithm())).intValue();
    }

    static AlgorithmIdentifier qTeslaLookupAlgID(int securityCategory) {
        switch (securityCategory) {
            case 5:
                return AlgID_qTESLA_p_I;
            case 6:
                return AlgID_qTESLA_p_III;
            default:
                throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static AlgorithmIdentifier sphincs256LookupTreeAlgID(String treeDigest) {
        if (treeDigest.equals("SHA3-256")) {
            return SPHINCS_SHA3_256;
        }
        if (treeDigest.equals(SPHINCSKeyParameters.SHA512_256)) {
            return SPHINCS_SHA512_256;
        }
        throw new IllegalArgumentException("unknown tree digest: " + treeDigest);
    }

    static AlgorithmIdentifier xmssLookupTreeAlgID(String treeDigest) {
        if (treeDigest.equals("SHA-256")) {
            return XMSS_SHA256;
        }
        if (treeDigest.equals("SHA-512")) {
            return XMSS_SHA512;
        }
        if (treeDigest.equals("SHAKE128")) {
            return XMSS_SHAKE128;
        }
        if (treeDigest.equals("SHAKE256")) {
            return XMSS_SHAKE256;
        }
        throw new IllegalArgumentException("unknown tree digest: " + treeDigest);
    }

    static String sphincs256LookupTreeAlgName(SPHINCS256KeyParams keyParams) {
        AlgorithmIdentifier treeDigest = keyParams.getTreeDigest();
        if (treeDigest.getAlgorithm().equals((ASN1Primitive) SPHINCS_SHA3_256.getAlgorithm())) {
            return "SHA3-256";
        }
        if (treeDigest.getAlgorithm().equals((ASN1Primitive) SPHINCS_SHA512_256.getAlgorithm())) {
            return SPHINCSKeyParameters.SHA512_256;
        }
        throw new IllegalArgumentException("unknown tree digest: " + treeDigest.getAlgorithm());
    }

    static Digest getDigest(ASN1ObjectIdentifier oid) {
        if (oid.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha256)) {
            return new SHA256Digest();
        }
        if (oid.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha512)) {
            return new SHA512Digest();
        }
        if (oid.equals((ASN1Primitive) NISTObjectIdentifiers.id_shake128)) {
            return new SHAKEDigest(128);
        }
        if (oid.equals((ASN1Primitive) NISTObjectIdentifiers.id_shake256)) {
            return new SHAKEDigest(256);
        }
        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }

    public static AlgorithmIdentifier getAlgorithmIdentifier(String digestName) {
        if (digestName.equals(McElieceCCA2KeyGenParameterSpec.SHA1)) {
            return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
        }
        if (digestName.equals(McElieceCCA2KeyGenParameterSpec.SHA224)) {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224);
        }
        if (digestName.equals("SHA-256")) {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        if (digestName.equals(McElieceCCA2KeyGenParameterSpec.SHA384)) {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
        }
        if (digestName.equals("SHA-512")) {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
        }
        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestName);
    }

    public static String getDigestName(ASN1ObjectIdentifier digestOid) {
        if (digestOid.equals((ASN1Primitive) OIWObjectIdentifiers.idSHA1)) {
            return McElieceCCA2KeyGenParameterSpec.SHA1;
        }
        if (digestOid.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha224)) {
            return McElieceCCA2KeyGenParameterSpec.SHA224;
        }
        if (digestOid.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha256)) {
            return "SHA-256";
        }
        if (digestOid.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha384)) {
            return McElieceCCA2KeyGenParameterSpec.SHA384;
        }
        if (digestOid.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha512)) {
            return "SHA-512";
        }
        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestOid);
    }

    static ASN1ObjectIdentifier sphincsPlusOidLookup(SPHINCSPlusParameters params) {
        int pId = SPHINCSPlusParameters.getID(params).intValue();
        if ((pId & 131072) == 131072) {
            return BCObjectIdentifiers.sphincsPlus_shake_256;
        }
        if ((pId & 5) == 5 || (pId & 6) == 6) {
            return BCObjectIdentifiers.sphincsPlus_sha_512;
        }
        return BCObjectIdentifiers.sphincsPlus_sha_256;
    }

    static ASN1ObjectIdentifier mcElieceOidLookup(CMCEParameters params) {
        return (ASN1ObjectIdentifier) mcElieceOids.get(params);
    }

    static CMCEParameters mcElieceParamsLookup(ASN1ObjectIdentifier oid) {
        return (CMCEParameters) mcElieceParams.get(oid);
    }

    static ASN1ObjectIdentifier frodoOidLookup(FrodoParameters params) {
        return (ASN1ObjectIdentifier) frodoOids.get(params);
    }

    static FrodoParameters frodoParamsLookup(ASN1ObjectIdentifier oid) {
        return (FrodoParameters) frodoParams.get(oid);
    }

    static ASN1ObjectIdentifier saberOidLookup(SABERParameters params) {
        return (ASN1ObjectIdentifier) saberOids.get(params);
    }

    static SABERParameters saberParamsLookup(ASN1ObjectIdentifier oid) {
        return (SABERParameters) saberParams.get(oid);
    }
}
