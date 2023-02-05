package com.mi.car.jsse.easysec.pqc.asn1;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;

public class McEliecePublicKey extends ASN1Object {
    private final GF2Matrix g;
    private final int n;
    private final int t;

    public McEliecePublicKey(int n2, int t2, GF2Matrix g2) {
        this.n = n2;
        this.t = t2;
        this.g = new GF2Matrix(g2);
    }

    private McEliecePublicKey(ASN1Sequence seq) {
        this.n = ((ASN1Integer) seq.getObjectAt(0)).intValueExact();
        this.t = ((ASN1Integer) seq.getObjectAt(1)).intValueExact();
        this.g = new GF2Matrix(((ASN1OctetString) seq.getObjectAt(2)).getOctets());
    }

    public int getN() {
        return this.n;
    }

    public int getT() {
        return this.t;
    }

    public GF2Matrix getG() {
        return new GF2Matrix(this.g);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer((long) this.n));
        v.add(new ASN1Integer((long) this.t));
        v.add(new DEROctetString(this.g.getEncoded()));
        return new DERSequence(v);
    }

    public static McEliecePublicKey getInstance(Object o) {
        if (o instanceof McEliecePublicKey) {
            return (McEliecePublicKey) o;
        }
        if (o != null) {
            return new McEliecePublicKey(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
