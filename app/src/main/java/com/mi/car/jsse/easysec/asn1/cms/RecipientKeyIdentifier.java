//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class RecipientKeyIdentifier extends ASN1Object {
    private ASN1OctetString subjectKeyIdentifier;
    private ASN1GeneralizedTime date;
    private OtherKeyAttribute other;

    public RecipientKeyIdentifier(ASN1OctetString subjectKeyIdentifier, ASN1GeneralizedTime date, OtherKeyAttribute other) {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
        this.date = date;
        this.other = other;
    }

    public RecipientKeyIdentifier(byte[] subjectKeyIdentifier, ASN1GeneralizedTime date, OtherKeyAttribute other) {
        this.subjectKeyIdentifier = new DEROctetString(subjectKeyIdentifier);
        this.date = date;
        this.other = other;
    }

    public RecipientKeyIdentifier(byte[] subjectKeyIdentifier) {
        this((byte[])subjectKeyIdentifier, (ASN1GeneralizedTime)null, (OtherKeyAttribute)null);
    }

    private RecipientKeyIdentifier(ASN1Sequence seq) {
        this.subjectKeyIdentifier = ASN1OctetString.getInstance(seq.getObjectAt(0));
        switch(seq.size()) {
            case 1:
                break;
            case 2:
                if (seq.getObjectAt(1) instanceof ASN1GeneralizedTime) {
                    this.date = ASN1GeneralizedTime.getInstance(seq.getObjectAt(1));
                } else {
                    this.other = OtherKeyAttribute.getInstance(seq.getObjectAt(2));
                }
                break;
            case 3:
                this.date = ASN1GeneralizedTime.getInstance(seq.getObjectAt(1));
                this.other = OtherKeyAttribute.getInstance(seq.getObjectAt(2));
                break;
            default:
                throw new IllegalArgumentException("Invalid RecipientKeyIdentifier");
        }

    }

    public static RecipientKeyIdentifier getInstance(ASN1TaggedObject ato, boolean isExplicit) {
        return getInstance(ASN1Sequence.getInstance(ato, isExplicit));
    }

    public static RecipientKeyIdentifier getInstance(Object obj) {
        if (obj instanceof RecipientKeyIdentifier) {
            return (RecipientKeyIdentifier)obj;
        } else {
            return obj != null ? new RecipientKeyIdentifier(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1OctetString getSubjectKeyIdentifier() {
        return this.subjectKeyIdentifier;
    }

    public ASN1GeneralizedTime getDate() {
        return this.date;
    }

    public OtherKeyAttribute getOtherKeyAttribute() {
        return this.other;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.subjectKeyIdentifier);
        if (this.date != null) {
            v.add(this.date);
        }

        if (this.other != null) {
            v.add(this.other);
        }

        return new DERSequence(v);
    }
}
