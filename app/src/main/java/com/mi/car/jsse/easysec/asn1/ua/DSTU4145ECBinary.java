package com.mi.car.jsse.easysec.asn1.ua;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.crypto.params.ECDomainParameters;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.field.PolynomialExtensionField;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class DSTU4145ECBinary extends ASN1Object {
    ASN1Integer a;
    ASN1OctetString b;
    ASN1OctetString bp;
    DSTU4145BinaryField f;
    ASN1Integer n;
    BigInteger version = BigInteger.valueOf(0);

    public DSTU4145ECBinary(ECDomainParameters params) {
        ECCurve curve = params.getCurve();
        if (!ECAlgorithms.isF2mCurve(curve)) {
            throw new IllegalArgumentException("only binary domain is possible");
        }
        int[] exponents = ((PolynomialExtensionField) curve.getField()).getMinimalPolynomial().getExponentsPresent();
        if (exponents.length == 3) {
            this.f = new DSTU4145BinaryField(exponents[2], exponents[1]);
        } else if (exponents.length == 5) {
            this.f = new DSTU4145BinaryField(exponents[4], exponents[1], exponents[2], exponents[3]);
        } else {
            throw new IllegalArgumentException("curve must have a trinomial or pentanomial basis");
        }
        this.a = new ASN1Integer(curve.getA().toBigInteger());
        this.b = new DEROctetString(curve.getB().getEncoded());
        this.n = new ASN1Integer(params.getN());
        this.bp = new DEROctetString(DSTU4145PointEncoder.encodePoint(params.getG()));
    }

    private DSTU4145ECBinary(ASN1Sequence seq) {
        int index = 0;
        if (seq.getObjectAt(0) instanceof ASN1TaggedObject) {
            ASN1TaggedObject taggedVersion = (ASN1TaggedObject) seq.getObjectAt(0);
            if (!taggedVersion.isExplicit() || taggedVersion.getTagNo() != 0) {
                throw new IllegalArgumentException("object parse error");
            }
            this.version = ASN1Integer.getInstance(taggedVersion.getLoadedObject()).getValue();
            index = 0 + 1;
        }
        this.f = DSTU4145BinaryField.getInstance(seq.getObjectAt(index));
        int index2 = index + 1;
        this.a = ASN1Integer.getInstance(seq.getObjectAt(index2));
        int index3 = index2 + 1;
        this.b = ASN1OctetString.getInstance(seq.getObjectAt(index3));
        int index4 = index3 + 1;
        this.n = ASN1Integer.getInstance(seq.getObjectAt(index4));
        this.bp = ASN1OctetString.getInstance(seq.getObjectAt(index4 + 1));
    }

    public static DSTU4145ECBinary getInstance(Object obj) {
        if (obj instanceof DSTU4145ECBinary) {
            return (DSTU4145ECBinary) obj;
        }
        if (obj != null) {
            return new DSTU4145ECBinary(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public DSTU4145BinaryField getField() {
        return this.f;
    }

    public BigInteger getA() {
        return this.a.getValue();
    }

    public byte[] getB() {
        return Arrays.clone(this.b.getOctets());
    }

    public BigInteger getN() {
        return this.n.getValue();
    }

    public byte[] getG() {
        return Arrays.clone(this.bp.getOctets());
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(6);
        if (this.version.compareTo(BigInteger.valueOf(0)) != 0) {
            v.add(new DERTaggedObject(true, 0, (ASN1Encodable) new ASN1Integer(this.version)));
        }
        v.add(this.f);
        v.add(this.a);
        v.add(this.b);
        v.add(this.n);
        v.add(this.bp);
        return new DERSequence(v);
    }
}
