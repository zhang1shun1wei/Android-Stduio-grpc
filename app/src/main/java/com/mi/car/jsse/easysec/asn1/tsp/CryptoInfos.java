package com.mi.car.jsse.easysec.asn1.tsp;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.cms.Attribute;

public class CryptoInfos extends ASN1Object {
    private ASN1Sequence attributes;

    public static CryptoInfos getInstance(Object obj) {
        if (obj instanceof CryptoInfos) {
            return (CryptoInfos) obj;
        }
        if (obj != null) {
            return new CryptoInfos(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static CryptoInfos getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    private CryptoInfos(ASN1Sequence attributes2) {
        this.attributes = attributes2;
    }

    public CryptoInfos(Attribute[] attrs) {
        this.attributes = new DERSequence(attrs);
    }

    public Attribute[] getAttributes() {
        Attribute[] rv = new Attribute[this.attributes.size()];
        for (int i = 0; i != rv.length; i++) {
            rv[i] = Attribute.getInstance(this.attributes.getObjectAt(i));
        }
        return rv;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.attributes;
    }
}
