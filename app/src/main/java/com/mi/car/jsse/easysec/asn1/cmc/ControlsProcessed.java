//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class ControlsProcessed extends ASN1Object {
    private final ASN1Sequence bodyPartReferences;

    public ControlsProcessed(BodyPartReference bodyPartRef) {
        this.bodyPartReferences = new DERSequence(bodyPartRef);
    }

    public ControlsProcessed(BodyPartReference[] bodyList) {
        this.bodyPartReferences = new DERSequence(bodyList);
    }

    public static ControlsProcessed getInstance(Object src) {
        if (src instanceof ControlsProcessed) {
            return (ControlsProcessed)src;
        } else {
            return src != null ? new ControlsProcessed(ASN1Sequence.getInstance(src)) : null;
        }
    }

    private ControlsProcessed(ASN1Sequence seq) {
        if (seq.size() != 1) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.bodyPartReferences = ASN1Sequence.getInstance(seq.getObjectAt(0));
        }
    }

    public BodyPartReference[] getBodyList() {
        BodyPartReference[] tmp = new BodyPartReference[this.bodyPartReferences.size()];

        for(int i = 0; i != this.bodyPartReferences.size(); ++i) {
            tmp[i] = BodyPartReference.getInstance(this.bodyPartReferences.getObjectAt(i));
        }

        return tmp;
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(this.bodyPartReferences);
    }
}