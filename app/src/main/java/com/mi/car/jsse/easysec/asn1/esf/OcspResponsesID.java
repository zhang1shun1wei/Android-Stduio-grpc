package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class OcspResponsesID extends ASN1Object {
    private OcspIdentifier ocspIdentifier;
    private OtherHash ocspRepHash;

    public static OcspResponsesID getInstance(Object obj) {
        if (obj instanceof OcspResponsesID) {
            return (OcspResponsesID) obj;
        }
        if (obj != null) {
            return new OcspResponsesID(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private OcspResponsesID(ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.ocspIdentifier = OcspIdentifier.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.ocspRepHash = OtherHash.getInstance(seq.getObjectAt(1));
        }
    }

    public OcspResponsesID(OcspIdentifier ocspIdentifier2) {
        this(ocspIdentifier2, null);
    }

    public OcspResponsesID(OcspIdentifier ocspIdentifier2, OtherHash ocspRepHash2) {
        this.ocspIdentifier = ocspIdentifier2;
        this.ocspRepHash = ocspRepHash2;
    }

    public OcspIdentifier getOcspIdentifier() {
        return this.ocspIdentifier;
    }

    public OtherHash getOcspRepHash() {
        return this.ocspRepHash;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.ocspIdentifier);
        if (this.ocspRepHash != null) {
            v.add(this.ocspRepHash);
        }
        return new DERSequence(v);
    }
}
