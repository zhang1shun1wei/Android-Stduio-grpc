package com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;

class DigestUtil {
    DigestUtil() {
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
}
