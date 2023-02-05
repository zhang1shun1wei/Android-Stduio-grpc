//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import com.mi.car.jsse.easysec.asn1.x509.ReasonFlags;

public class GetCRL extends ASN1Object {
    private final X500Name issuerName;
    private GeneralName cRLName;
    private ASN1GeneralizedTime time;
    private ReasonFlags reasons;

    public GetCRL(X500Name issuerName, GeneralName cRLName, ASN1GeneralizedTime time, ReasonFlags reasons) {
        this.issuerName = issuerName;
        this.cRLName = cRLName;
        this.time = time;
        this.reasons = reasons;
    }

    private GetCRL(ASN1Sequence seq) {
        if (seq.size() >= 1 && seq.size() <= 4) {
            this.issuerName = X500Name.getInstance(seq.getObjectAt(0));
            int index = 1;
            if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() instanceof ASN1TaggedObject) {
                this.cRLName = GeneralName.getInstance(seq.getObjectAt(index++));
            }

            if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() instanceof ASN1GeneralizedTime) {
                this.time = ASN1GeneralizedTime.getInstance(seq.getObjectAt(index++));
            }

            if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() instanceof ASN1BitString) {
                this.reasons = new ReasonFlags(ASN1BitString.getInstance(seq.getObjectAt(index)));
            }

        } else {
            throw new IllegalArgumentException("incorrect sequence size");
        }
    }

    public static GetCRL getInstance(Object o) {
        if (o instanceof GetCRL) {
            return (GetCRL)o;
        } else {
            return o != null ? new GetCRL(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public X500Name getIssuerName() {
        return this.issuerName;
    }

    public GeneralName getcRLName() {
        return this.cRLName;
    }

    public ASN1GeneralizedTime getTime() {
        return this.time;
    }

    public ReasonFlags getReasons() {
        return this.reasons;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.issuerName);
        if (this.cRLName != null) {
            v.add(this.cRLName);
        }

        if (this.time != null) {
            v.add(this.time);
        }

        if (this.reasons != null) {
            v.add(this.reasons);
        }

        return new DERSequence(v);
    }
}