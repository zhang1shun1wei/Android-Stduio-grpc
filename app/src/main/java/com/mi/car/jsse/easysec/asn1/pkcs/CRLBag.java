package com.mi.car.jsse.easysec.asn1.pkcs;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class CRLBag extends ASN1Object {
    private ASN1ObjectIdentifier crlId;
    private ASN1Encodable crlValue;

    private CRLBag(ASN1Sequence seq) {
        this.crlId = (ASN1ObjectIdentifier) seq.getObjectAt(0);
        this.crlValue = ((ASN1TaggedObject) seq.getObjectAt(1)).getObject();
    }

    public static CRLBag getInstance(Object o) {
        if (o instanceof CRLBag) {
            return (CRLBag) o;
        }
        if (o != null) {
            return new CRLBag(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public CRLBag(ASN1ObjectIdentifier crlId2, ASN1Encodable crlValue2) {
        this.crlId = crlId2;
        this.crlValue = crlValue2;
    }

    public ASN1ObjectIdentifier getCrlId() {
        return this.crlId;
    }

    public ASN1Encodable getCrlValue() {
        return this.crlValue;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.crlId);
        v.add(new DERTaggedObject(0, this.crlValue));
        return new DERSequence(v);
    }
}
