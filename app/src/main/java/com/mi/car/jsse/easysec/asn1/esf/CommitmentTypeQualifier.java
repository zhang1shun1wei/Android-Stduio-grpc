package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class CommitmentTypeQualifier extends ASN1Object {
    private ASN1ObjectIdentifier commitmentTypeIdentifier;
    private ASN1Encodable qualifier;

    public CommitmentTypeQualifier(ASN1ObjectIdentifier commitmentTypeIdentifier) {
        this(commitmentTypeIdentifier, (ASN1Encodable)null);
    }

    public CommitmentTypeQualifier(ASN1ObjectIdentifier commitmentTypeIdentifier, ASN1Encodable qualifier) {
        this.commitmentTypeIdentifier = commitmentTypeIdentifier;
        this.qualifier = qualifier;
    }

    private CommitmentTypeQualifier(ASN1Sequence as) {
        this.commitmentTypeIdentifier = (ASN1ObjectIdentifier)as.getObjectAt(0);
        if (as.size() > 1) {
            this.qualifier = as.getObjectAt(1);
        }

    }

    public static CommitmentTypeQualifier getInstance(Object as) {
        if (as instanceof CommitmentTypeQualifier) {
            return (CommitmentTypeQualifier)as;
        } else {
            return as != null ? new CommitmentTypeQualifier(ASN1Sequence.getInstance(as)) : null;
        }
    }

    public ASN1ObjectIdentifier getCommitmentTypeIdentifier() {
        return this.commitmentTypeIdentifier;
    }

    public ASN1Encodable getQualifier() {
        return this.qualifier;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector dev = new ASN1EncodableVector(2);
        dev.add(this.commitmentTypeIdentifier);
        if (this.qualifier != null) {
            dev.add(this.qualifier);
        }

        return new DERSequence(dev);
    }
}
