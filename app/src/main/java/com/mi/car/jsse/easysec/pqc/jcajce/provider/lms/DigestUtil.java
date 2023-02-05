package com.mi.car.jsse.easysec.pqc.jcajce.provider.lms;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Xof;

class DigestUtil {
    DigestUtil() {
    }

    public static byte[] getDigestResult(Digest digest) {
        byte[] hash = new byte[getDigestSize(digest)];
        if (digest instanceof Xof) {
            ((Xof) digest).doFinal(hash, 0, hash.length);
        } else {
            digest.doFinal(hash, 0);
        }
        return hash;
    }

    public static int getDigestSize(Digest digest) {
        if (digest instanceof Xof) {
            return digest.getDigestSize() * 2;
        }
        return digest.getDigestSize();
    }

    public static String getXMSSDigestName(ASN1ObjectIdentifier treeDigest) {
        if (treeDigest.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha256)) {
            return "SHA256";
        }
        if (treeDigest.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha512)) {
            return "SHA512";
        }
        if (treeDigest.equals((ASN1Primitive) NISTObjectIdentifiers.id_shake128)) {
            return "SHAKE128";
        }
        if (treeDigest.equals((ASN1Primitive) NISTObjectIdentifiers.id_shake256)) {
            return "SHAKE256";
        }
        throw new IllegalArgumentException("unrecognized digest OID: " + treeDigest);
    }
}
