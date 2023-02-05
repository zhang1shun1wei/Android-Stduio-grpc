package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.ocsp.ResponderID;

public class OcspIdentifier extends ASN1Object {
    private ResponderID ocspResponderID;
    private ASN1GeneralizedTime producedAt;

    public static OcspIdentifier getInstance(Object obj) {
        if (obj instanceof OcspIdentifier) {
            return (OcspIdentifier)obj;
        } else {
            return obj != null ? new OcspIdentifier(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    private OcspIdentifier(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        } else {
            this.ocspResponderID = ResponderID.getInstance(seq.getObjectAt(0));
            this.producedAt = (ASN1GeneralizedTime)seq.getObjectAt(1);
        }
    }

    public OcspIdentifier(ResponderID ocspResponderID, ASN1GeneralizedTime producedAt) {
        this.ocspResponderID = ocspResponderID;
        this.producedAt = producedAt;
    }

    public ResponderID getOcspResponderID() {
        return this.ocspResponderID;
    }

    public ASN1GeneralizedTime getProducedAt() {
        return this.producedAt;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.ocspResponderID);
        v.add(this.producedAt);
        return new DERSequence(v);
    }
}
