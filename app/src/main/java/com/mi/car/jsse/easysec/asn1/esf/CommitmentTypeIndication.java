package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class CommitmentTypeIndication extends ASN1Object {
    private ASN1ObjectIdentifier commitmentTypeId;
    private ASN1Sequence commitmentTypeQualifier;

    private CommitmentTypeIndication(ASN1Sequence seq) {
        this.commitmentTypeId = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        if (seq.size() > 1) {
            this.commitmentTypeQualifier = (ASN1Sequence)seq.getObjectAt(1);
        }

    }

    public CommitmentTypeIndication(ASN1ObjectIdentifier commitmentTypeId) {
        this.commitmentTypeId = commitmentTypeId;
    }

    public CommitmentTypeIndication(ASN1ObjectIdentifier commitmentTypeId, ASN1Sequence commitmentTypeQualifier) {
        this.commitmentTypeId = commitmentTypeId;
        this.commitmentTypeQualifier = commitmentTypeQualifier;
    }

    public static CommitmentTypeIndication getInstance(Object obj) {
        return obj != null && !(obj instanceof CommitmentTypeIndication) ? new CommitmentTypeIndication(ASN1Sequence.getInstance(obj)) : (CommitmentTypeIndication)obj;
    }

    public ASN1ObjectIdentifier getCommitmentTypeId() {
        return this.commitmentTypeId;
    }

    public ASN1Sequence getCommitmentTypeQualifier() {
        return this.commitmentTypeQualifier;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.commitmentTypeId);
        if (this.commitmentTypeQualifier != null) {
            v.add(this.commitmentTypeQualifier);
        }

        return new DERSequence(v);
    }
}
