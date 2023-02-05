package com.mi.car.jsse.easysec.asn1.isismtt.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.x500.DirectoryString;

public class Restriction extends ASN1Object {
    private DirectoryString restriction;

    public static Restriction getInstance(Object obj) {
        if (obj instanceof Restriction) {
            return (Restriction) obj;
        }
        if (obj != null) {
            return new Restriction(DirectoryString.getInstance(obj));
        }
        return null;
    }

    private Restriction(DirectoryString restriction2) {
        this.restriction = restriction2;
    }

    public Restriction(String restriction2) {
        this.restriction = new DirectoryString(restriction2);
    }

    public DirectoryString getRestriction() {
        return this.restriction;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.restriction.toASN1Primitive();
    }
}
