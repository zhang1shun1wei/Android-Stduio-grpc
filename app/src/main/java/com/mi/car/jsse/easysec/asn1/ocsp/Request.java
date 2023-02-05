package com.mi.car.jsse.easysec.asn1.ocsp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;

public class Request extends ASN1Object {
    CertID reqCert;
    Extensions singleRequestExtensions;

    public Request(CertID reqCert2, Extensions singleRequestExtensions2) {
        this.reqCert = reqCert2;
        this.singleRequestExtensions = singleRequestExtensions2;
    }

    private Request(ASN1Sequence seq) {
        this.reqCert = CertID.getInstance(seq.getObjectAt(0));
        if (seq.size() == 2) {
            this.singleRequestExtensions = Extensions.getInstance((ASN1TaggedObject) seq.getObjectAt(1), true);
        }
    }

    public static Request getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Request getInstance(Object obj) {
        if (obj instanceof Request) {
            return (Request) obj;
        }
        if (obj != null) {
            return new Request(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public CertID getReqCert() {
        return this.reqCert;
    }

    public Extensions getSingleRequestExtensions() {
        return this.singleRequestExtensions;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.reqCert);
        if (this.singleRequestExtensions != null) {
            v.add(new DERTaggedObject(true, 0, (ASN1Encodable) this.singleRequestExtensions));
        }
        return new DERSequence(v);
    }
}
