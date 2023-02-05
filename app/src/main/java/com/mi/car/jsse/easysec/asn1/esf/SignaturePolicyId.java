package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class SignaturePolicyId extends ASN1Object {
    private OtherHashAlgAndValue sigPolicyHash;
    private ASN1ObjectIdentifier sigPolicyId;
    private SigPolicyQualifiers sigPolicyQualifiers;

    public static SignaturePolicyId getInstance(Object obj) {
        if (obj instanceof SignaturePolicyId) {
            return (SignaturePolicyId) obj;
        }
        if (obj != null) {
            return new SignaturePolicyId(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private SignaturePolicyId(ASN1Sequence seq) {
        if (seq.size() == 2 || seq.size() == 3) {
            this.sigPolicyId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            this.sigPolicyHash = OtherHashAlgAndValue.getInstance(seq.getObjectAt(1));
            if (seq.size() == 3) {
                this.sigPolicyQualifiers = SigPolicyQualifiers.getInstance(seq.getObjectAt(2));
                return;
            }
            return;
        }
        throw new IllegalArgumentException("Bad sequence size: " + seq.size());
    }

    public SignaturePolicyId(ASN1ObjectIdentifier sigPolicyIdentifier, OtherHashAlgAndValue sigPolicyHash2) {
        this(sigPolicyIdentifier, sigPolicyHash2, null);
    }

    public SignaturePolicyId(ASN1ObjectIdentifier sigPolicyId2, OtherHashAlgAndValue sigPolicyHash2, SigPolicyQualifiers sigPolicyQualifiers2) {
        this.sigPolicyId = sigPolicyId2;
        this.sigPolicyHash = sigPolicyHash2;
        this.sigPolicyQualifiers = sigPolicyQualifiers2;
    }

    public ASN1ObjectIdentifier getSigPolicyId() {
        return new ASN1ObjectIdentifier(this.sigPolicyId.getId());
    }

    public OtherHashAlgAndValue getSigPolicyHash() {
        return this.sigPolicyHash;
    }

    public SigPolicyQualifiers getSigPolicyQualifiers() {
        return this.sigPolicyQualifiers;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.sigPolicyId);
        v.add(this.sigPolicyHash);
        if (this.sigPolicyQualifiers != null) {
            v.add(this.sigPolicyQualifiers);
        }
        return new DERSequence(v);
    }
}
