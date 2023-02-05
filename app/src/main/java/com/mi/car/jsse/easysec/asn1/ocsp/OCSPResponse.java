package com.mi.car.jsse.easysec.asn1.ocsp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class OCSPResponse extends ASN1Object {
    ResponseBytes responseBytes;
    OCSPResponseStatus responseStatus;

    public OCSPResponse(OCSPResponseStatus responseStatus2, ResponseBytes responseBytes2) {
        this.responseStatus = responseStatus2;
        this.responseBytes = responseBytes2;
    }

    private OCSPResponse(ASN1Sequence seq) {
        this.responseStatus = OCSPResponseStatus.getInstance(seq.getObjectAt(0));
        if (seq.size() == 2) {
            this.responseBytes = ResponseBytes.getInstance((ASN1TaggedObject) seq.getObjectAt(1), true);
        }
    }

    public static OCSPResponse getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OCSPResponse getInstance(Object obj) {
        if (obj instanceof OCSPResponse) {
            return (OCSPResponse) obj;
        }
        if (obj != null) {
            return new OCSPResponse(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public OCSPResponseStatus getResponseStatus() {
        return this.responseStatus;
    }

    public ResponseBytes getResponseBytes() {
        return this.responseBytes;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.responseStatus);
        if (this.responseBytes != null) {
            v.add(new DERTaggedObject(true, 0, (ASN1Encodable) this.responseBytes));
        }
        return new DERSequence(v);
    }
}
