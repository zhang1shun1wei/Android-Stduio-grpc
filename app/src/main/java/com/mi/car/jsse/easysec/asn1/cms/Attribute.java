//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

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
        if (o instanceof Attribute) {
            return (Attribute)o;
        } else {
            return o != null ? new Attribute(ASN1Sequence.getInstance(o)) : null;
        }
    }

    private Attribute(ASN1Sequence seq) {
        this.attrType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        this.attrValues = (ASN1Set)seq.getObjectAt(1);
    }

    public Attribute(ASN1ObjectIdentifier attrType, ASN1Set attrValues) {
        this.attrType = attrType;
        this.attrValues = attrValues;
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

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.attrType);
        v.add(this.attrValues);
        return new DERSequence(v);
    }
}
