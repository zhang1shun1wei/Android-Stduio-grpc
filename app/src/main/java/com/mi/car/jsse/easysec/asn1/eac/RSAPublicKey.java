package com.mi.car.jsse.easysec.asn1.eac;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.math.BigInteger;
import java.util.Enumeration;

public class RSAPublicKey extends PublicKeyDataObject {
    private static int exponentValid = 2;
    private static int modulusValid = 1;
    private BigInteger exponent;
    private BigInteger modulus;
    private ASN1ObjectIdentifier usage;
    private int valid = 0;

    RSAPublicKey(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        this.usage = ASN1ObjectIdentifier.getInstance(en.nextElement());
        while (en.hasMoreElements()) {
            UnsignedInteger val = UnsignedInteger.getInstance(en.nextElement());
            switch (val.getTagNo()) {
                case 1:
                    setModulus(val);
                    break;
                case 2:
                    setExponent(val);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown DERTaggedObject :" + val.getTagNo() + "-> not an Iso7816RSAPublicKeyStructure");
            }
        }
        if (this.valid != 3) {
            throw new IllegalArgumentException("missing argument -> not an Iso7816RSAPublicKeyStructure");
        }
    }

    public RSAPublicKey(ASN1ObjectIdentifier usage2, BigInteger modulus2, BigInteger exponent2) {
        this.usage = usage2;
        this.modulus = modulus2;
        this.exponent = exponent2;
    }

    @Override // com.mi.car.jsse.easysec.asn1.eac.PublicKeyDataObject
    public ASN1ObjectIdentifier getUsage() {
        return this.usage;
    }

    public BigInteger getModulus() {
        return this.modulus;
    }

    public BigInteger getPublicExponent() {
        return this.exponent;
    }

    private void setModulus(UnsignedInteger modulus2) {
        if ((this.valid & modulusValid) == 0) {
            this.valid |= modulusValid;
            this.modulus = modulus2.getValue();
            return;
        }
        throw new IllegalArgumentException("Modulus already set");
    }

    private void setExponent(UnsignedInteger exponent2) {
        if ((this.valid & exponentValid) == 0) {
            this.valid |= exponentValid;
            this.exponent = exponent2.getValue();
            return;
        }
        throw new IllegalArgumentException("Exponent already set");
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.usage);
        v.add(new UnsignedInteger(1, getModulus()));
        v.add(new UnsignedInteger(2, getPublicExponent()));
        return new DERSequence(v);
    }
}
