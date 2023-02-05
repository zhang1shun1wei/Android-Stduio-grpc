//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class BodyPartList extends ASN1Object {
    private final BodyPartID[] bodyPartIDs;

    public static BodyPartList getInstance(Object obj) {
        if (obj instanceof BodyPartList) {
            return (BodyPartList)obj;
        } else {
            return obj != null ? new BodyPartList(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public static BodyPartList getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public BodyPartList(BodyPartID bodyPartID) {
        this.bodyPartIDs = new BodyPartID[]{bodyPartID};
    }

    public BodyPartList(BodyPartID[] bodyPartIDs) {
        this.bodyPartIDs = Utils.clone(bodyPartIDs);
    }

    private BodyPartList(ASN1Sequence seq) {
        this.bodyPartIDs = Utils.toBodyPartIDArray(seq);
    }

    public BodyPartID[] getBodyPartIDs() {
        return Utils.clone(this.bodyPartIDs);
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(this.bodyPartIDs);
    }
}