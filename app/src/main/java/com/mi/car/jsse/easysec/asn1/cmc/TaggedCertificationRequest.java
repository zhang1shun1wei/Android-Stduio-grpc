//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class TaggedCertificationRequest extends ASN1Object {
    private final BodyPartID bodyPartID;
    private final CertificationRequest certificationRequest;

    public TaggedCertificationRequest(BodyPartID bodyPartID, CertificationRequest certificationRequest) {
        this.bodyPartID = bodyPartID;
        this.certificationRequest = certificationRequest;
    }

    private TaggedCertificationRequest(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
            this.certificationRequest = CertificationRequest.getInstance(seq.getObjectAt(1));
        }
    }

    public static TaggedCertificationRequest getInstance(Object o) {
        if (o instanceof TaggedCertificationRequest) {
            return (TaggedCertificationRequest)o;
        } else {
            return o != null ? new TaggedCertificationRequest(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public static TaggedCertificationRequest getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.bodyPartID);
        v.add(this.certificationRequest);
        return new DERSequence(v);
    }
}