package com.mi.car.jsse.easysec.asn1.x9;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class X9Curve extends ASN1Object implements X9ObjectIdentifiers {
    private ECCurve curve;
    private ASN1ObjectIdentifier fieldIdentifier;
    private byte[] seed;

    public X9Curve(ECCurve curve2) {
        this(curve2, null);
    }

    public X9Curve(ECCurve curve2, byte[] seed2) {
        this.fieldIdentifier = null;
        this.curve = curve2;
        this.seed = Arrays.clone(seed2);
        setFieldIdentifier();
    }

    public X9Curve(X9FieldID fieldID, BigInteger order, BigInteger cofactor, ASN1Sequence seq) {
        int k1;
        this.fieldIdentifier = null;
        this.fieldIdentifier = fieldID.getIdentifier();
        if (this.fieldIdentifier.equals((ASN1Primitive) prime_field)) {
            this.curve = new ECCurve.Fp(((ASN1Integer) fieldID.getParameters()).getValue(), new BigInteger(1, ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets()), new BigInteger(1, ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets()), order, cofactor);
        } else if (this.fieldIdentifier.equals((ASN1Primitive) characteristic_two_field)) {
            ASN1Sequence parameters = ASN1Sequence.getInstance(fieldID.getParameters());
            int m = ((ASN1Integer) parameters.getObjectAt(0)).intValueExact();
            ASN1ObjectIdentifier representation = (ASN1ObjectIdentifier) parameters.getObjectAt(1);
            int k2 = 0;
            int k3 = 0;
            if (representation.equals((ASN1Primitive) tpBasis)) {
                k1 = ASN1Integer.getInstance(parameters.getObjectAt(2)).intValueExact();
            } else if (representation.equals((ASN1Primitive) ppBasis)) {
                ASN1Sequence pentanomial = ASN1Sequence.getInstance(parameters.getObjectAt(2));
                k1 = ASN1Integer.getInstance(pentanomial.getObjectAt(0)).intValueExact();
                k2 = ASN1Integer.getInstance(pentanomial.getObjectAt(1)).intValueExact();
                k3 = ASN1Integer.getInstance(pentanomial.getObjectAt(2)).intValueExact();
            } else {
                throw new IllegalArgumentException("This type of EC basis is not implemented");
            }
            this.curve = new ECCurve.F2m(m, k1, k2, k3, new BigInteger(1, ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets()), new BigInteger(1, ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets()), order, cofactor);
        } else {
            throw new IllegalArgumentException("This type of ECCurve is not implemented");
        }
        if (seq.size() == 3) {
            this.seed = ((DERBitString) seq.getObjectAt(2)).getBytes();
        }
    }

    private void setFieldIdentifier() {
        if (ECAlgorithms.isFpCurve(this.curve)) {
            this.fieldIdentifier = prime_field;
        } else if (ECAlgorithms.isF2mCurve(this.curve)) {
            this.fieldIdentifier = characteristic_two_field;
        } else {
            throw new IllegalArgumentException("This type of ECCurve is not implemented");
        }
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.seed);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        if (this.fieldIdentifier.equals((ASN1Primitive) prime_field)) {
            v.add(new X9FieldElement(this.curve.getA()).toASN1Primitive());
            v.add(new X9FieldElement(this.curve.getB()).toASN1Primitive());
        } else if (this.fieldIdentifier.equals((ASN1Primitive) characteristic_two_field)) {
            v.add(new X9FieldElement(this.curve.getA()).toASN1Primitive());
            v.add(new X9FieldElement(this.curve.getB()).toASN1Primitive());
        }
        if (this.seed != null) {
            v.add(new DERBitString(this.seed));
        }
        return new DERSequence(v);
    }
}
