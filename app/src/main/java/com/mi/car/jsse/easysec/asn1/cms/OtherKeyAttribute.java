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
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class OtherKeyAttribute extends ASN1Object {
    private ASN1ObjectIdentifier keyAttrId;
    private ASN1Encodable keyAttr;

    public static OtherKeyAttribute getInstance(Object o) {
        if (o instanceof OtherKeyAttribute) {
            return (OtherKeyAttribute)o;
        } else {
            return o != null ? new OtherKeyAttribute(ASN1Sequence.getInstance(o)) : null;
        }
    }

    private OtherKeyAttribute(ASN1Sequence seq) {
        this.keyAttrId = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        this.keyAttr = seq.getObjectAt(1);
    }

    public OtherKeyAttribute(ASN1ObjectIdentifier keyAttrId, ASN1Encodable keyAttr) {
        this.keyAttrId = keyAttrId;
        this.keyAttr = keyAttr;
    }

    public ASN1ObjectIdentifier getKeyAttrId() {
        return this.keyAttrId;
    }

    public ASN1Encodable getKeyAttr() {
        return this.keyAttr;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.keyAttrId);
        v.add(this.keyAttr);
        return new DERSequence(v);
    }
}
