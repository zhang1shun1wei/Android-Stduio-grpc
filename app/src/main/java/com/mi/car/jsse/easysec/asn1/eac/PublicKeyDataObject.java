package com.mi.car.jsse.easysec.asn1.eac;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;

public abstract class PublicKeyDataObject extends ASN1Object {
    public abstract ASN1ObjectIdentifier getUsage();

    public static PublicKeyDataObject getInstance(Object obj) {
        if (obj instanceof PublicKeyDataObject) {
            return (PublicKeyDataObject) obj;
        }
        if (obj == null) {
            return null;
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(obj);
        if (ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0)).on(EACObjectIdentifiers.id_TA_ECDSA)) {
            return new ECDSAPublicKey(seq);
        }
        return new RSAPublicKey(seq);
    }
}
