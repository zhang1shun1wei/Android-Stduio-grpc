package com.mi.car.jsse.easysec.asn1.pkcs;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.math.BigInteger;
import java.util.Enumeration;

public class RSAPublicKey extends ASN1Object {
    private BigInteger modulus;
    private BigInteger publicExponent;

    public static RSAPublicKey getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RSAPublicKey getInstance(Object obj) {
        if (obj instanceof RSAPublicKey) {
            return (RSAPublicKey) obj;
        }
        if (obj != null) {
            return new RSAPublicKey(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public RSAPublicKey(BigInteger modulus2, BigInteger publicExponent2) {
        this.modulus = modulus2;
        this.publicExponent = publicExponent2;
    }

    private RSAPublicKey(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        this.modulus = ASN1Integer.getInstance(e.nextElement()).getPositiveValue();
        this.publicExponent = ASN1Integer.getInstance(e.nextElement()).getPositiveValue();
    }

    public BigInteger getModulus() {
        return this.modulus;
    }

    public BigInteger getPublicExponent() {
        return this.publicExponent;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(new ASN1Integer(getModulus()));
        v.add(new ASN1Integer(getPublicExponent()));
        return new DERSequence(v);
    }
}
