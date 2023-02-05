//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Null;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.DERNull;

public class PKIConfirmContent extends ASN1Object {
    private final ASN1Null val;

    private PKIConfirmContent(ASN1Null val) {
        this.val = val;
    }

    public PKIConfirmContent() {
        this.val = DERNull.INSTANCE;
    }

    public static PKIConfirmContent getInstance(Object o) {
        if (o != null && !(o instanceof PKIConfirmContent)) {
            if (o instanceof ASN1Null) {
                return new PKIConfirmContent((ASN1Null)o);
            } else {
                throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
            }
        } else {
            return (PKIConfirmContent)o;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        return this.val;
    }
}
