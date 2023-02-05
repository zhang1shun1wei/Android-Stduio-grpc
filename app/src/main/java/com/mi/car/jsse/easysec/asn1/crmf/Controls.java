package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class Controls extends ASN1Object {
    private ASN1Sequence content;

    private Controls(ASN1Sequence seq) {
        this.content = seq;
    }

    public static Controls getInstance(Object o) {
        if (o instanceof Controls) {
            return (Controls) o;
        }
        if (o != null) {
            return new Controls(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public Controls(AttributeTypeAndValue atv) {
        this.content = new DERSequence(atv);
    }

    public Controls(AttributeTypeAndValue[] atvs) {
        this.content = new DERSequence(atvs);
    }

    public AttributeTypeAndValue[] toAttributeTypeAndValueArray() {
        AttributeTypeAndValue[] result = new AttributeTypeAndValue[this.content.size()];
        for (int i = 0; i != result.length; i++) {
            result[i] = AttributeTypeAndValue.getInstance(this.content.getObjectAt(i));
        }
        return result;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.content;
    }
}
