package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.util.DigestFactory;

class Utils {
    Utils() {
    }

    static Digest getDigest(AlgorithmIdentifier digest) {
        if (digest.getAlgorithm().equals((ASN1Primitive) OIWObjectIdentifiers.idSHA1)) {
            return DigestFactory.createSHA1();
        }
        if (digest.getAlgorithm().equals((ASN1Primitive) NISTObjectIdentifiers.id_sha224)) {
            return DigestFactory.createSHA224();
        }
        if (digest.getAlgorithm().equals((ASN1Primitive) NISTObjectIdentifiers.id_sha256)) {
            return DigestFactory.createSHA256();
        }
        if (digest.getAlgorithm().equals((ASN1Primitive) NISTObjectIdentifiers.id_sha384)) {
            return DigestFactory.createSHA384();
        }
        if (digest.getAlgorithm().equals((ASN1Primitive) NISTObjectIdentifiers.id_sha512)) {
            return DigestFactory.createSHA512();
        }
        throw new IllegalArgumentException("unrecognised OID in digest algorithm identifier: " + digest.getAlgorithm());
    }
}
