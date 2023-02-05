package com.mi.car.jsse.easysec.asn1.x9;

import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import java.math.BigInteger;

public class DHPublicKey extends ASN1Object {
    private ASN1Integer y;

    public static DHPublicKey getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Integer.getInstance(obj, explicit));
    }

    public static DHPublicKey getInstance(Object obj) {
        if (obj == null || (obj instanceof DHPublicKey)) {
            return (DHPublicKey) obj;
        }
        if (obj instanceof ASN1Integer) {
            return new DHPublicKey((ASN1Integer) obj);
        }
        throw new IllegalArgumentException("Invalid DHPublicKey: " + obj.getClass().getName());
    }

    private DHPublicKey(ASN1Integer y2) {
        if (y2 == null) {
            throw new IllegalArgumentException("'y' cannot be null");
        }
        this.y = y2;
    }

    public DHPublicKey(BigInteger y2) {
        if (y2 == null) {
            throw new IllegalArgumentException("'y' cannot be null");
        }
        this.y = new ASN1Integer(y2);
    }

    public BigInteger getY() {
        return this.y.getPositiveValue();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.y;
    }
}
