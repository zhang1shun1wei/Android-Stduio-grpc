package com.mi.car.jsse.easysec.asn1.ocsp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class ResponseBytes extends ASN1Object {
    ASN1OctetString response;
    ASN1ObjectIdentifier responseType;

    public ResponseBytes(ASN1ObjectIdentifier responseType2, ASN1OctetString response2) {
        this.responseType = responseType2;
        this.response = response2;
    }

    private ResponseBytes(ASN1Sequence seq) {
        this.responseType = (ASN1ObjectIdentifier) seq.getObjectAt(0);
        this.response = (ASN1OctetString) seq.getObjectAt(1);
    }

    public static ResponseBytes getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ResponseBytes getInstance(Object obj) {
        if (obj instanceof ResponseBytes) {
            return (ResponseBytes) obj;
        }
        if (obj != null) {
            return new ResponseBytes(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ASN1ObjectIdentifier getResponseType() {
        return this.responseType;
    }

    public ASN1OctetString getResponse() {
        return this.response;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.responseType);
        v.add(this.response);
        return new DERSequence(v);
    }
}
