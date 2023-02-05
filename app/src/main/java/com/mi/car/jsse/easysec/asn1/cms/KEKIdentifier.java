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

public class KEKIdentifier extends ASN1Object {
    private ASN1OctetString keyIdentifier;
    private ASN1GeneralizedTime date;
    private OtherKeyAttribute other;

    public KEKIdentifier(byte[] keyIdentifier, ASN1GeneralizedTime date, OtherKeyAttribute other) {
        this.keyIdentifier = new DEROctetString(keyIdentifier);
        this.date = date;
        this.other = other;
    }

    private KEKIdentifier(ASN1Sequence seq) {
        this.keyIdentifier = (ASN1OctetString)seq.getObjectAt(0);
        switch(seq.size()) {
            case 1:
                break;
            case 2:
                if (seq.getObjectAt(1) instanceof ASN1GeneralizedTime) {
                    this.date = (ASN1GeneralizedTime)seq.getObjectAt(1);
                } else {
                    this.other = OtherKeyAttribute.getInstance(seq.getObjectAt(1));
                }
                break;
            case 3:
                this.date = (ASN1GeneralizedTime)seq.getObjectAt(1);
                this.other = OtherKeyAttribute.getInstance(seq.getObjectAt(2));
                break;
            default:
                throw new IllegalArgumentException("Invalid KEKIdentifier");
        }

    }

    public static KEKIdentifier getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static KEKIdentifier getInstance(Object obj) {
        if (obj != null && !(obj instanceof KEKIdentifier)) {
            if (obj instanceof ASN1Sequence) {
                return new KEKIdentifier((ASN1Sequence)obj);
            } else {
                throw new IllegalArgumentException("Invalid KEKIdentifier: " + obj.getClass().getName());
            }
        } else {
            return (KEKIdentifier)obj;
        }
    }

    public ASN1OctetString getKeyIdentifier() {
        return this.keyIdentifier;
    }

    public ASN1GeneralizedTime getDate() {
        return this.date;
    }

    public OtherKeyAttribute getOther() {
        return this.other;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.keyIdentifier);
        if (this.date != null) {
            v.add(this.date);
        }

        if (this.other != null) {
            v.add(this.other);
        }

        return new DERSequence(v);
    }
}
