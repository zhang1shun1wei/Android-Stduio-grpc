//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class SCVPReqRes extends ASN1Object {
    private final ContentInfo request;
    private final ContentInfo response;

    public static SCVPReqRes getInstance(Object obj) {
        if (obj instanceof SCVPReqRes) {
            return (SCVPReqRes)obj;
        } else {
            return obj != null ? new SCVPReqRes(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    private SCVPReqRes(ASN1Sequence seq) {
        if (seq.getObjectAt(0) instanceof ASN1TaggedObject) {
            this.request = ContentInfo.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(0)), true);
            this.response = ContentInfo.getInstance(seq.getObjectAt(1));
        } else {
            this.request = null;
            this.response = ContentInfo.getInstance(seq.getObjectAt(0));
        }

    }

    public SCVPReqRes(ContentInfo response) {
        this.request = null;
        this.response = response;
    }

    public SCVPReqRes(ContentInfo request, ContentInfo response) {
        this.request = request;
        this.response = response;
    }

    public ContentInfo getRequest() {
        return this.request;
    }

    public ContentInfo getResponse() {
        return this.response;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        if (this.request != null) {
            v.add(new DERTaggedObject(true, 0, this.request));
        }

        v.add(this.response);
        return new DERSequence(v);
    }
}
