package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;

public class CRLNumber extends ASN1Object {
    private BigInteger number;

    public CRLNumber(BigInteger number2) {
        if (BigIntegers.ZERO.compareTo(number2) > 0) {
            throw new IllegalArgumentException("Invalid CRL number : not in (0..MAX)");
        }
        this.number = number2;
    }

    public BigInteger getCRLNumber() {
        return this.number;
    }

    public String toString() {
        return "CRLNumber: " + getCRLNumber();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new ASN1Integer(this.number);
    }

    public static CRLNumber getInstance(Object o) {
        if (o instanceof CRLNumber) {
            return (CRLNumber) o;
        }
        if (o != null) {
            return new CRLNumber(ASN1Integer.getInstance(o).getValue());
        }
        return null;
    }
}
