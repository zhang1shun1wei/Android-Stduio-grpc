package com.mi.car.jsse.easysec.asn1.pkcs;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class Attribute extends ASN1Object {
    private ASN1ObjectIdentifier attrType;
    private ASN1Set attrValues;

    public static Attribute getInstance(Object o) {
        if (o == null || (o instanceof Attribute)) {
            return (Attribute) o;
        }
        if (o instanceof ASN1Sequence) {
            return new Attribute((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
    }

    public Attribute(ASN1Sequence seq) {
        this.attrType = (ASN1ObjectIdentifier) seq.getObjectAt(0);
        this.attrValues = (ASN1Set) seq.getObjectAt(1);
    }

    public Attribute(ASN1ObjectIdentifier attrType2, ASN1Set attrValues2) {
        this.attrType = attrType2;
        this.attrValues = attrValues2;
    }

    public ASN1ObjectIdentifier getAttrType() {
        return this.attrType;
    }

    public ASN1Set getAttrValues() {
        return this.attrValues;
    }

    public ASN1Encodable[] getAttributeValues() {
        return this.attrValues.toArray();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.attrType);
        v.add(this.attrValues);
        return new DERSequence(v);
    }
}
