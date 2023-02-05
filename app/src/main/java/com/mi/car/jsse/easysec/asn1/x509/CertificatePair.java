package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.util.Enumeration;

public class CertificatePair extends ASN1Object {
    private Certificate forward;
    private Certificate reverse;

    public static CertificatePair getInstance(Object obj) {
        if (obj == null || (obj instanceof CertificatePair)) {
            return (CertificatePair) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new CertificatePair((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private CertificatePair(ASN1Sequence seq) {
        if (seq.size() == 1 || seq.size() == 2) {
            Enumeration e = seq.getObjects();
            while (e.hasMoreElements()) {
                ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
                if (o.getTagNo() == 0) {
                    this.forward = Certificate.getInstance(o, true);
                } else if (o.getTagNo() == 1) {
                    this.reverse = Certificate.getInstance(o, true);
                } else {
                    throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
                }
            }
            return;
        }
        throw new IllegalArgumentException("Bad sequence size: " + seq.size());
    }

    public CertificatePair(Certificate forward2, Certificate reverse2) {
        this.forward = forward2;
        this.reverse = reverse2;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(2);
        if (this.forward != null) {
            vec.add(new DERTaggedObject(0, this.forward));
        }
        if (this.reverse != null) {
            vec.add(new DERTaggedObject(1, this.reverse));
        }
        return new DERSequence(vec);
    }

    public Certificate getForward() {
        return this.forward;
    }

    public Certificate getReverse() {
        return this.reverse;
    }
}
