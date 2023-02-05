package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class SigPolicyQualifierInfo extends ASN1Object {
    private ASN1ObjectIdentifier sigPolicyQualifierId;
    private ASN1Encodable sigQualifier;

    public SigPolicyQualifierInfo(ASN1ObjectIdentifier sigPolicyQualifierId2, ASN1Encodable sigQualifier2) {
        this.sigPolicyQualifierId = sigPolicyQualifierId2;
        this.sigQualifier = sigQualifier2;
    }

    private SigPolicyQualifierInfo(ASN1Sequence seq) {
        this.sigPolicyQualifierId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.sigQualifier = seq.getObjectAt(1);
    }

    public static SigPolicyQualifierInfo getInstance(Object obj) {
        if (obj instanceof SigPolicyQualifierInfo) {
            return (SigPolicyQualifierInfo) obj;
        }
        if (obj != null) {
            return new SigPolicyQualifierInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ASN1ObjectIdentifier getSigPolicyQualifierId() {
        return new ASN1ObjectIdentifier(this.sigPolicyQualifierId.getId());
    }

    public ASN1Encodable getSigQualifier() {
        return this.sigQualifier;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.sigPolicyQualifierId);
        v.add(this.sigQualifier);
        return new DERSequence(v);
    }
}
