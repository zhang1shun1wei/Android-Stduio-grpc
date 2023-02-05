package com.mi.car.jsse.easysec.asn1.x9;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;

public class X9FieldElement extends ASN1Object {
    private static X9IntegerConverter converter = new X9IntegerConverter();
    protected ECFieldElement f;

    public X9FieldElement(ECFieldElement f2) {
        this.f = f2;
    }

    public ECFieldElement getValue() {
        return this.f;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DEROctetString(converter.integerToBytes(this.f.toBigInteger(), converter.getByteLength(this.f)));
    }
}
