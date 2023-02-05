//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DLSet;

public class Attributes extends ASN1Object {
    private ASN1Set attributes;

    private Attributes(ASN1Set set) {
        this.attributes = set;
    }

    public Attributes(ASN1EncodableVector v) {
        this.attributes = new DLSet(v);
    }

    public static Attributes getInstance(Object obj) {
        if (obj instanceof Attributes) {
            return (Attributes)obj;
        } else {
            return obj != null ? new Attributes(ASN1Set.getInstance(obj)) : null;
        }
    }

    public static Attributes getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Set.getInstance(obj, explicit));
    }

    public Attribute[] getAttributes() {
        Attribute[] rv = new Attribute[this.attributes.size()];

        for(int i = 0; i != rv.length; ++i) {
            rv[i] = Attribute.getInstance(this.attributes.getObjectAt(i));
        }

        return rv;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.attributes;
    }
}
