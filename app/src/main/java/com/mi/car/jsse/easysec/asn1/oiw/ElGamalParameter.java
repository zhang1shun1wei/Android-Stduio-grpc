package com.mi.car.jsse.easysec.asn1.oiw;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.math.BigInteger;
import java.util.Enumeration;

public class ElGamalParameter extends ASN1Object {
    ASN1Integer g;
    ASN1Integer p;

    public ElGamalParameter(BigInteger p2, BigInteger g2) {
        this.p = new ASN1Integer(p2);
        this.g = new ASN1Integer(g2);
    }

    private ElGamalParameter(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.p = (ASN1Integer) e.nextElement();
        this.g = (ASN1Integer) e.nextElement();
    }

    public static ElGamalParameter getInstance(Object o) {
        if (o instanceof ElGamalParameter) {
            return (ElGamalParameter) o;
        }
        if (o != null) {
            return new ElGamalParameter(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public BigInteger getP() {
        return this.p.getPositiveValue();
    }

    public BigInteger getG() {
        return this.g.getPositiveValue();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.p);
        v.add(this.g);
        return new DERSequence(v);
    }
}
