package com.mi.car.jsse.easysec.pqc.asn1;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Matrix;

public class McElieceCCA2PublicKey extends ASN1Object {
    private final AlgorithmIdentifier digest;
    private final GF2Matrix g;
    private final int n;
    private final int t;

    public McElieceCCA2PublicKey(int n2, int t2, GF2Matrix g2, AlgorithmIdentifier digest2) {
        this.n = n2;
        this.t = t2;
        this.g = new GF2Matrix(g2.getEncoded());
        this.digest = digest2;
    }

    private McElieceCCA2PublicKey(ASN1Sequence seq) {
        this.n = ((ASN1Integer) seq.getObjectAt(0)).intValueExact();
        this.t = ((ASN1Integer) seq.getObjectAt(1)).intValueExact();
        this.g = new GF2Matrix(((ASN1OctetString) seq.getObjectAt(2)).getOctets());
        this.digest = AlgorithmIdentifier.getInstance(seq.getObjectAt(3));
    }

    public int getN() {
        return this.n;
    }

    public int getT() {
        return this.t;
    }

    public GF2Matrix getG() {
        return this.g;
    }

    public AlgorithmIdentifier getDigest() {
        return this.digest;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer((long) this.n));
        v.add(new ASN1Integer((long) this.t));
        v.add(new DEROctetString(this.g.getEncoded()));
        v.add(this.digest);
        return new DERSequence(v);
    }

    public static McElieceCCA2PublicKey getInstance(Object o) {
        if (o instanceof McElieceCCA2PublicKey) {
            return (McElieceCCA2PublicKey) o;
        }
        if (o != null) {
            return new McElieceCCA2PublicKey(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
