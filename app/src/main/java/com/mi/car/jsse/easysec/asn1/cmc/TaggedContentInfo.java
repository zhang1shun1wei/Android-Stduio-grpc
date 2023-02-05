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
import com.mi.car.jsse.easysec.asn1.cms.ContentInfo;

public class TaggedContentInfo extends ASN1Object {
    private final BodyPartID bodyPartID;
    private final ContentInfo contentInfo;

    public TaggedContentInfo(BodyPartID bodyPartID, ContentInfo contentInfo) {
        this.bodyPartID = bodyPartID;
        this.contentInfo = contentInfo;
    }

    private TaggedContentInfo(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
            this.contentInfo = ContentInfo.getInstance(seq.getObjectAt(1));
        }
    }

    public static TaggedContentInfo getInstance(Object o) {
        if (o instanceof TaggedContentInfo) {
            return (TaggedContentInfo)o;
        } else {
            return o != null ? new TaggedContentInfo(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public static TaggedContentInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.bodyPartID);
        v.add(this.contentInfo);
        return new DERSequence(v);
    }

    public BodyPartID getBodyPartID() {
        return this.bodyPartID;
    }

    public ContentInfo getContentInfo() {
        return this.contentInfo;
    }
}