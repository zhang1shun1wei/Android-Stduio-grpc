package com.mi.car.jsse.easysec.asn1.cryptopro;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.math.BigInteger;
import java.util.Enumeration;

public class GOST3410ParamSetParameters extends ASN1Object {
    ASN1Integer a;
    int keySize;
    ASN1Integer p;
    ASN1Integer q;

    public static GOST3410ParamSetParameters getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static GOST3410ParamSetParameters getInstance(Object obj) {
        if (obj == null || (obj instanceof GOST3410ParamSetParameters)) {
            return (GOST3410ParamSetParameters) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new GOST3410ParamSetParameters((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid GOST3410Parameter: " + obj.getClass().getName());
    }

    public GOST3410ParamSetParameters(int keySize2, BigInteger p2, BigInteger q2, BigInteger a2) {
        this.keySize = keySize2;
        this.p = new ASN1Integer(p2);
        this.q = new ASN1Integer(q2);
        this.a = new ASN1Integer(a2);
    }

    public GOST3410ParamSetParameters(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.keySize = ((ASN1Integer) e.nextElement()).intValueExact();
        this.p = (ASN1Integer) e.nextElement();
        this.q = (ASN1Integer) e.nextElement();
        this.a = (ASN1Integer) e.nextElement();
    }

    public int getLKeySize() {
        return this.keySize;
    }

    public int getKeySize() {
        return this.keySize;
    }

    public BigInteger getP() {
        return this.p.getPositiveValue();
    }

    public BigInteger getQ() {
        return this.q.getPositiveValue();
    }

    public BigInteger getA() {
        return this.a.getPositiveValue();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(new ASN1Integer((long) this.keySize));
        v.add(this.p);
        v.add(this.q);
        v.add(this.a);
        return new DERSequence(v);
    }
}
