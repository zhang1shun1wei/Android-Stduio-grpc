package com.mi.car.jsse.easysec.asn1.ua;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class DSTU4145BinaryField extends ASN1Object {
    private int j;
    private int k;
    private int l;
    private int m;

    private DSTU4145BinaryField(ASN1Sequence seq) {
        this.m = ASN1Integer.getInstance(seq.getObjectAt(0)).intPositiveValueExact();
        if (seq.getObjectAt(1) instanceof ASN1Integer) {
            this.k = ((ASN1Integer) seq.getObjectAt(1)).intPositiveValueExact();
        } else if (seq.getObjectAt(1) instanceof ASN1Sequence) {
            ASN1Sequence coefs = ASN1Sequence.getInstance(seq.getObjectAt(1));
            this.k = ASN1Integer.getInstance(coefs.getObjectAt(0)).intPositiveValueExact();
            this.j = ASN1Integer.getInstance(coefs.getObjectAt(1)).intPositiveValueExact();
            this.l = ASN1Integer.getInstance(coefs.getObjectAt(2)).intPositiveValueExact();
        } else {
            throw new IllegalArgumentException("object parse error");
        }
    }

    public static DSTU4145BinaryField getInstance(Object obj) {
        if (obj instanceof DSTU4145BinaryField) {
            return (DSTU4145BinaryField) obj;
        }
        if (obj != null) {
            return new DSTU4145BinaryField(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public DSTU4145BinaryField(int m2, int k1, int k2, int k3) {
        this.m = m2;
        this.k = k1;
        this.j = k2;
        this.l = k3;
    }

    public int getM() {
        return this.m;
    }

    public int getK1() {
        return this.k;
    }

    public int getK2() {
        return this.j;
    }

    public int getK3() {
        return this.l;
    }

    public DSTU4145BinaryField(int m2, int k2) {
        this(m2, k2, 0, 0);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(new ASN1Integer((long) this.m));
        if (this.j == 0) {
            v.add(new ASN1Integer((long) this.k));
        } else {
            ASN1EncodableVector coefs = new ASN1EncodableVector(3);
            coefs.add(new ASN1Integer((long) this.k));
            coefs.add(new ASN1Integer((long) this.j));
            coefs.add(new ASN1Integer((long) this.l));
            v.add(new DERSequence(coefs));
        }
        return new DERSequence(v);
    }
}
