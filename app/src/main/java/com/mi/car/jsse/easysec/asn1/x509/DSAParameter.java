package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.math.BigInteger;
import java.util.Enumeration;

public class DSAParameter extends ASN1Object {
    ASN1Integer g;
    ASN1Integer p;
    ASN1Integer q;

    public static DSAParameter getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static DSAParameter getInstance(Object obj) {
        if (obj instanceof DSAParameter) {
            return (DSAParameter) obj;
        }
        if (obj != null) {
            return new DSAParameter(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public DSAParameter(BigInteger p2, BigInteger q2, BigInteger g2) {
        this.p = new ASN1Integer(p2);
        this.q = new ASN1Integer(q2);
        this.g = new ASN1Integer(g2);
    }

    private DSAParameter(ASN1Sequence seq) {
        if (seq.size() != 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        this.p = ASN1Integer.getInstance(e.nextElement());
        this.q = ASN1Integer.getInstance(e.nextElement());
        this.g = ASN1Integer.getInstance(e.nextElement());
    }

    public BigInteger getP() {
        return this.p.getPositiveValue();
    }

    public BigInteger getQ() {
        return this.q.getPositiveValue();
    }

    public BigInteger getG() {
        return this.g.getPositiveValue();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.p);
        v.add(this.q);
        v.add(this.g);
        return new DERSequence(v);
    }
}
