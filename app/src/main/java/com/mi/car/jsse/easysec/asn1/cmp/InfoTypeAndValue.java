//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class InfoTypeAndValue extends ASN1Object {
    private final ASN1ObjectIdentifier infoType;
    private ASN1Encodable infoValue;

    private InfoTypeAndValue(ASN1Sequence seq) {
        this.infoType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.infoValue = seq.getObjectAt(1);
        }

    }

    public InfoTypeAndValue(ASN1ObjectIdentifier infoType) {
        this.infoType = infoType;
        this.infoValue = null;
    }

    public InfoTypeAndValue(ASN1ObjectIdentifier infoType, ASN1Encodable optionalValue) {
        this.infoType = infoType;
        this.infoValue = optionalValue;
    }

    public static InfoTypeAndValue getInstance(Object o) {
        if (o instanceof InfoTypeAndValue) {
            return (InfoTypeAndValue)o;
        } else {
            return o != null ? new InfoTypeAndValue(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ASN1ObjectIdentifier getInfoType() {
        return this.infoType;
    }

    public ASN1Encodable getInfoValue() {
        return this.infoValue;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.infoType);
        if (this.infoValue != null) {
            v.add(this.infoValue);
        }

        return new DERSequence(v);
    }
}
