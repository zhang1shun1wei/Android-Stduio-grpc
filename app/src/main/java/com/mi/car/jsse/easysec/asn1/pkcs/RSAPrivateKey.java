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

public class RSAPrivateKey extends ASN1Object {
    private BigInteger coefficient;
    private BigInteger exponent1;
    private BigInteger exponent2;
    private BigInteger modulus;
    private ASN1Sequence otherPrimeInfos;
    private BigInteger prime1;
    private BigInteger prime2;
    private BigInteger privateExponent;
    private BigInteger publicExponent;
    private BigInteger version;

    public static RSAPrivateKey getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RSAPrivateKey getInstance(Object obj) {
        if (obj instanceof RSAPrivateKey) {
            return (RSAPrivateKey) obj;
        }
        if (obj != null) {
            return new RSAPrivateKey(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public RSAPrivateKey(BigInteger modulus2, BigInteger publicExponent2, BigInteger privateExponent2, BigInteger prime12, BigInteger prime22, BigInteger exponent12, BigInteger exponent22, BigInteger coefficient2) {
        this.otherPrimeInfos = null;
        this.version = BigInteger.valueOf(0);
        this.modulus = modulus2;
        this.publicExponent = publicExponent2;
        this.privateExponent = privateExponent2;
        this.prime1 = prime12;
        this.prime2 = prime22;
        this.exponent1 = exponent12;
        this.exponent2 = exponent22;
        this.coefficient = coefficient2;
    }

    private RSAPrivateKey(ASN1Sequence seq) {
        this.otherPrimeInfos = null;
        Enumeration e = seq.getObjects();
        ASN1Integer v = (ASN1Integer) e.nextElement();
        int versionValue = v.intValueExact();
        if (versionValue < 0 || versionValue > 1) {
            throw new IllegalArgumentException("wrong version for RSA private key");
        }
        this.version = v.getValue();
        this.modulus = ((ASN1Integer) e.nextElement()).getValue();
        this.publicExponent = ((ASN1Integer) e.nextElement()).getValue();
        this.privateExponent = ((ASN1Integer) e.nextElement()).getValue();
        this.prime1 = ((ASN1Integer) e.nextElement()).getValue();
        this.prime2 = ((ASN1Integer) e.nextElement()).getValue();
        this.exponent1 = ((ASN1Integer) e.nextElement()).getValue();
        this.exponent2 = ((ASN1Integer) e.nextElement()).getValue();
        this.coefficient = ((ASN1Integer) e.nextElement()).getValue();
        if (e.hasMoreElements()) {
            this.otherPrimeInfos = (ASN1Sequence) e.nextElement();
        }
    }

    public BigInteger getVersion() {
        return this.version;
    }

    public BigInteger getModulus() {
        return this.modulus;
    }

    public BigInteger getPublicExponent() {
        return this.publicExponent;
    }

    public BigInteger getPrivateExponent() {
        return this.privateExponent;
    }

    public BigInteger getPrime1() {
        return this.prime1;
    }

    public BigInteger getPrime2() {
        return this.prime2;
    }

    public BigInteger getExponent1() {
        return this.exponent1;
    }

    public BigInteger getExponent2() {
        return this.exponent2;
    }

    public BigInteger getCoefficient() {
        return this.coefficient;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(10);
        v.add(new ASN1Integer(this.version));
        v.add(new ASN1Integer(getModulus()));
        v.add(new ASN1Integer(getPublicExponent()));
        v.add(new ASN1Integer(getPrivateExponent()));
        v.add(new ASN1Integer(getPrime1()));
        v.add(new ASN1Integer(getPrime2()));
        v.add(new ASN1Integer(getExponent1()));
        v.add(new ASN1Integer(getExponent2()));
        v.add(new ASN1Integer(getCoefficient()));
        if (this.otherPrimeInfos != null) {
            v.add(this.otherPrimeInfos);
        }
        return new DERSequence(v);
    }
}
