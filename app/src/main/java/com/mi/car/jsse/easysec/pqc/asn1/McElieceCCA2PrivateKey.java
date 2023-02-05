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
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2mField;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.Permutation;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.PolynomialGF2mSmallM;

public class McElieceCCA2PrivateKey extends ASN1Object {
    private AlgorithmIdentifier digest;
    private byte[] encField;
    private byte[] encGp;
    private byte[] encP;
    private int k;
    private int n;

    public McElieceCCA2PrivateKey(int n2, int k2, GF2mField field, PolynomialGF2mSmallM goppaPoly, Permutation p, AlgorithmIdentifier digest2) {
        this.n = n2;
        this.k = k2;
        this.encField = field.getEncoded();
        this.encGp = goppaPoly.getEncoded();
        this.encP = p.getEncoded();
        this.digest = digest2;
    }

    private McElieceCCA2PrivateKey(ASN1Sequence seq) {
        this.n = ((ASN1Integer) seq.getObjectAt(0)).intValueExact();
        this.k = ((ASN1Integer) seq.getObjectAt(1)).intValueExact();
        this.encField = ((ASN1OctetString) seq.getObjectAt(2)).getOctets();
        this.encGp = ((ASN1OctetString) seq.getObjectAt(3)).getOctets();
        this.encP = ((ASN1OctetString) seq.getObjectAt(4)).getOctets();
        this.digest = AlgorithmIdentifier.getInstance(seq.getObjectAt(5));
    }

    public int getN() {
        return this.n;
    }

    public int getK() {
        return this.k;
    }

    public GF2mField getField() {
        return new GF2mField(this.encField);
    }

    public PolynomialGF2mSmallM getGoppaPoly() {
        return new PolynomialGF2mSmallM(getField(), this.encGp);
    }

    public Permutation getP() {
        return new Permutation(this.encP);
    }

    public AlgorithmIdentifier getDigest() {
        return this.digest;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer((long) this.n));
        v.add(new ASN1Integer((long) this.k));
        v.add(new DEROctetString(this.encField));
        v.add(new DEROctetString(this.encGp));
        v.add(new DEROctetString(this.encP));
        v.add(this.digest);
        return new DERSequence(v);
    }

    public static McElieceCCA2PrivateKey getInstance(Object o) {
        if (o instanceof McElieceCCA2PrivateKey) {
            return (McElieceCCA2PrivateKey) o;
        }
        if (o != null) {
            return new McElieceCCA2PrivateKey(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
