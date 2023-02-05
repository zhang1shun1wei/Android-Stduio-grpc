package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class CrlValidatedID extends ASN1Object {
    private OtherHash crlHash;
    private CrlIdentifier crlIdentifier;

    public static CrlValidatedID getInstance(Object obj) {
        if (obj instanceof CrlValidatedID) {
            return (CrlValidatedID) obj;
        }
        if (obj != null) {
            return new CrlValidatedID(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private CrlValidatedID(ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.crlHash = OtherHash.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.crlIdentifier = CrlIdentifier.getInstance(seq.getObjectAt(1));
        }
    }

    public CrlValidatedID(OtherHash crlHash2) {
        this(crlHash2, null);
    }

    public CrlValidatedID(OtherHash crlHash2, CrlIdentifier crlIdentifier2) {
        this.crlHash = crlHash2;
        this.crlIdentifier = crlIdentifier2;
    }

    public OtherHash getCrlHash() {
        return this.crlHash;
    }

    public CrlIdentifier getCrlIdentifier() {
        return this.crlIdentifier;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.crlHash.toASN1Primitive());
        if (this.crlIdentifier != null) {
            v.add(this.crlIdentifier.toASN1Primitive());
        }
        return new DERSequence(v);
    }
}
