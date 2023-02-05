//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class OtherRecipientInfo extends ASN1Object {
    private ASN1ObjectIdentifier oriType;
    private ASN1Encodable oriValue;

    public OtherRecipientInfo(ASN1ObjectIdentifier oriType, ASN1Encodable oriValue) {
        this.oriType = oriType;
        this.oriValue = oriValue;
    }

    private OtherRecipientInfo(ASN1Sequence seq) {
        this.oriType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.oriValue = seq.getObjectAt(1);
    }

    public static OtherRecipientInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OtherRecipientInfo getInstance(Object obj) {
        if (obj instanceof OtherRecipientInfo) {
            return (OtherRecipientInfo)obj;
        } else {
            return obj != null ? new OtherRecipientInfo(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1ObjectIdentifier getType() {
        return this.oriType;
    }

    public ASN1Encodable getValue() {
        return this.oriValue;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.oriType);
        v.add(this.oriValue);
        return new DERSequence(v);
    }
}
