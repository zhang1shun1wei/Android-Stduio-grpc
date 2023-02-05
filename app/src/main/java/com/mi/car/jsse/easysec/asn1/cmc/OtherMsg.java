//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class OtherMsg extends ASN1Object {
    private final BodyPartID bodyPartID;
    private final ASN1ObjectIdentifier otherMsgType;
    private final ASN1Encodable otherMsgValue;

    public OtherMsg(BodyPartID bodyPartID, ASN1ObjectIdentifier otherMsgType, ASN1Encodable otherMsgValue) {
        this.bodyPartID = bodyPartID;
        this.otherMsgType = otherMsgType;
        this.otherMsgValue = otherMsgValue;
    }

    private OtherMsg(ASN1Sequence seq) {
        if (seq.size() != 3) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
            this.otherMsgType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
            this.otherMsgValue = seq.getObjectAt(2);
        }
    }

    public static OtherMsg getInstance(Object o) {
        if (o instanceof OtherMsg) {
            return (OtherMsg)o;
        } else {
            return o != null ? new OtherMsg(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public static OtherMsg getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.bodyPartID);
        v.add(this.otherMsgType);
        v.add(this.otherMsgValue);
        return new DERSequence(v);
    }

    public BodyPartID getBodyPartID() {
        return this.bodyPartID;
    }

    public ASN1ObjectIdentifier getOtherMsgType() {
        return this.otherMsgType;
    }

    public ASN1Encodable getOtherMsgValue() {
        return this.otherMsgValue;
    }
}