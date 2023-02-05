//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class PKIResponse extends ASN1Object {
    private final ASN1Sequence controlSequence;
    private final ASN1Sequence cmsSequence;
    private final ASN1Sequence otherMsgSequence;

    private PKIResponse(ASN1Sequence seq) {
        if (seq.size() != 3) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.controlSequence = ASN1Sequence.getInstance(seq.getObjectAt(0));
            this.cmsSequence = ASN1Sequence.getInstance(seq.getObjectAt(1));
            this.otherMsgSequence = ASN1Sequence.getInstance(seq.getObjectAt(2));
        }
    }

    public static PKIResponse getInstance(Object o) {
        if (o instanceof PKIResponse) {
            return (PKIResponse)o;
        } else {
            return o != null ? new PKIResponse(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public static PKIResponse getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.controlSequence);
        v.add(this.cmsSequence);
        v.add(this.otherMsgSequence);
        return new DERSequence(v);
    }

    public ASN1Sequence getControlSequence() {
        return this.controlSequence;
    }

    public ASN1Sequence getCmsSequence() {
        return this.cmsSequence;
    }

    public ASN1Sequence getOtherMsgSequence() {
        return this.otherMsgSequence;
    }
}