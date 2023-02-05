package com.mi.car.jsse.easysec.asn1.x9;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.field.PolynomialExtensionField;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class X9ECParameters extends ASN1Object implements X9ObjectIdentifiers {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private ECCurve curve;
    private X9FieldID fieldID;
    private X9ECPoint g;
    private BigInteger h;
    private BigInteger n;
    private byte[] seed;

    private X9ECParameters(ASN1Sequence seq) {
        if (!(seq.getObjectAt(0) instanceof ASN1Integer) || !((ASN1Integer) seq.getObjectAt(0)).hasValue(1)) {
            throw new IllegalArgumentException("bad version in X9ECParameters");
        }
        this.n = ((ASN1Integer) seq.getObjectAt(4)).getValue();
        if (seq.size() == 6) {
            this.h = ((ASN1Integer) seq.getObjectAt(5)).getValue();
        }
        X9Curve x9c = new X9Curve(X9FieldID.getInstance(seq.getObjectAt(1)), this.n, this.h, ASN1Sequence.getInstance(seq.getObjectAt(2)));
        this.curve = x9c.getCurve();
        ASN1Encodable p = seq.getObjectAt(3);
        if (p instanceof X9ECPoint) {
            this.g = (X9ECPoint) p;
        } else {
            this.g = new X9ECPoint(this.curve, (ASN1OctetString) p);
        }
        this.seed = x9c.getSeed();
    }

    public static X9ECParameters getInstance(Object obj) {
        if (obj instanceof X9ECParameters) {
            return (X9ECParameters) obj;
        }
        if (obj != null) {
            return new X9ECParameters(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public X9ECParameters(ECCurve curve2, X9ECPoint g2, BigInteger n2) {
        this(curve2, g2, n2, null, null);
    }

    public X9ECParameters(ECCurve curve2, X9ECPoint g2, BigInteger n2, BigInteger h2) {
        this(curve2, g2, n2, h2, null);
    }

    public X9ECParameters(ECCurve curve2, X9ECPoint g2, BigInteger n2, BigInteger h2, byte[] seed2) {
        this.curve = curve2;
        this.g = g2;
        this.n = n2;
        this.h = h2;
        this.seed = Arrays.clone(seed2);
        if (ECAlgorithms.isFpCurve(curve2)) {
            this.fieldID = new X9FieldID(curve2.getField().getCharacteristic());
        } else if (ECAlgorithms.isF2mCurve(curve2)) {
            int[] exponents = ((PolynomialExtensionField) curve2.getField()).getMinimalPolynomial().getExponentsPresent();
            if (exponents.length == 3) {
                this.fieldID = new X9FieldID(exponents[2], exponents[1]);
            } else if (exponents.length == 5) {
                this.fieldID = new X9FieldID(exponents[4], exponents[1], exponents[2], exponents[3]);
            } else {
                throw new IllegalArgumentException("Only trinomial and pentomial curves are supported");
            }
        } else {
            throw new IllegalArgumentException("'curve' is of an unsupported type");
        }
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    public ECPoint getG() {
        return this.g.getPoint();
    }

    public BigInteger getN() {
        return this.n;
    }

    public BigInteger getH() {
        return this.h;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.seed);
    }

    public boolean hasSeed() {
        return this.seed != null;
    }

    public X9Curve getCurveEntry() {
        return new X9Curve(this.curve, this.seed);
    }

    public X9FieldID getFieldIDEntry() {
        return this.fieldID;
    }

    public X9ECPoint getBaseEntry() {
        return this.g;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(6);
        v.add(new ASN1Integer(ONE));
        v.add(this.fieldID);
        v.add(new X9Curve(this.curve, this.seed));
        v.add(this.g);
        v.add(new ASN1Integer(this.n));
        if (this.h != null) {
            v.add(new ASN1Integer(this.h));
        }
        return new DERSequence(v);
    }
}
