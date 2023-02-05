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

public class OtherRevocationInfoFormat extends ASN1Object {
    private ASN1ObjectIdentifier otherRevInfoFormat;
    private ASN1Encodable otherRevInfo;

    public OtherRevocationInfoFormat(ASN1ObjectIdentifier otherRevInfoFormat, ASN1Encodable otherRevInfo) {
        this.otherRevInfoFormat = otherRevInfoFormat;
        this.otherRevInfo = otherRevInfo;
    }

    private OtherRevocationInfoFormat(ASN1Sequence seq) {
        this.otherRevInfoFormat = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.otherRevInfo = seq.getObjectAt(1);
    }

    public static OtherRevocationInfoFormat getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OtherRevocationInfoFormat getInstance(Object obj) {
        if (obj instanceof OtherRevocationInfoFormat) {
            return (OtherRevocationInfoFormat)obj;
        } else {
            return obj != null ? new OtherRevocationInfoFormat(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1ObjectIdentifier getInfoFormat() {
        return this.otherRevInfoFormat;
    }

    public ASN1Encodable getInfo() {
        return this.otherRevInfo;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.otherRevInfoFormat);
        v.add(this.otherRevInfo);
        return new DERSequence(v);
    }
}
