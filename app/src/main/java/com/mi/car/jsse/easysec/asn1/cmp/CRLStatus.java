//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.Time;

public class CRLStatus extends ASN1Object {
    private final CRLSource source;
    private final Time time;

    private CRLStatus(ASN1Sequence sequence) {
        if (sequence.size() != 1 && sequence.size() != 2) {
            throw new IllegalArgumentException("expected sequence size of 1 or 2, got " + sequence.size());
        } else {
            this.source = CRLSource.getInstance(sequence.getObjectAt(0));
            if (sequence.size() == 2) {
                this.time = Time.getInstance(sequence.getObjectAt(1));
            } else {
                this.time = null;
            }

        }
    }

    public CRLStatus(CRLSource source, Time time) {
        this.source = source;
        this.time = time;
    }

    public static CRLStatus getInstance(Object o) {
        if (o instanceof CRLStatus) {
            return (CRLStatus)o;
        } else {
            return o != null ? new CRLStatus(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public CRLSource getSource() {
        return this.source;
    }

    public Time getTime() {
        return this.time;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.source);
        if (this.time != null) {
            v.add(this.time);
        }

        return new DERSequence(v);
    }
}
