package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.Time;
import java.util.Enumeration;

public class OptionalValidity extends ASN1Object {
    private Time notAfter;
    private Time notBefore;

    private OptionalValidity(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        while (en.hasMoreElements()) {
            ASN1TaggedObject tObj = (ASN1TaggedObject) en.nextElement();
            if (tObj.getTagNo() == 0) {
                this.notBefore = Time.getInstance(tObj, true);
            } else {
                this.notAfter = Time.getInstance(tObj, true);
            }
        }
    }

    public static OptionalValidity getInstance(Object o) {
        if (o instanceof OptionalValidity) {
            return (OptionalValidity) o;
        }
        if (o != null) {
            return new OptionalValidity(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public OptionalValidity(Time notBefore2, Time notAfter2) {
        if (notBefore2 == null && notAfter2 == null) {
            throw new IllegalArgumentException("at least one of notBefore/notAfter must not be null.");
        }
        this.notBefore = notBefore2;
        this.notAfter = notAfter2;
    }

    public Time getNotBefore() {
        return this.notBefore;
    }

    public Time getNotAfter() {
        return this.notAfter;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        if (this.notBefore != null) {
            v.add(new DERTaggedObject(true, 0, this.notBefore));
        }
        if (this.notAfter != null) {
            v.add(new DERTaggedObject(true, 1, this.notAfter));
        }
        return new DERSequence(v);
    }
}
