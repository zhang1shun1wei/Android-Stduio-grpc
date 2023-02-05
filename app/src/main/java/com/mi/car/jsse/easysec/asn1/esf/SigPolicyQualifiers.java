package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class SigPolicyQualifiers extends ASN1Object {
    ASN1Sequence qualifiers;

    public static SigPolicyQualifiers getInstance(Object obj) {
        if (obj instanceof SigPolicyQualifiers) {
            return (SigPolicyQualifiers) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new SigPolicyQualifiers(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private SigPolicyQualifiers(ASN1Sequence seq) {
        this.qualifiers = seq;
    }

    public SigPolicyQualifiers(SigPolicyQualifierInfo[] qualifierInfos) {
        this.qualifiers = new DERSequence(qualifierInfos);
    }

    public int size() {
        return this.qualifiers.size();
    }

    public SigPolicyQualifierInfo getInfoAt(int i) {
        return SigPolicyQualifierInfo.getInstance(this.qualifiers.getObjectAt(i));
    }

    public ASN1Primitive toASN1Primitive() {
        return this.qualifiers;
    }
}
