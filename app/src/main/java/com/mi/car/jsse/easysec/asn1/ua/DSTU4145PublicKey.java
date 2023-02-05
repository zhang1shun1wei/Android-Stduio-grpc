package com.mi.car.jsse.easysec.asn1.ua;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.math.ec.ECPoint;

public class DSTU4145PublicKey extends ASN1Object {
    private ASN1OctetString pubKey;

    public DSTU4145PublicKey(ECPoint pubKey2) {
        this.pubKey = new DEROctetString(DSTU4145PointEncoder.encodePoint(pubKey2));
    }

    private DSTU4145PublicKey(ASN1OctetString ocStr) {
        this.pubKey = ocStr;
    }

    public static DSTU4145PublicKey getInstance(Object obj) {
        if (obj instanceof DSTU4145PublicKey) {
            return (DSTU4145PublicKey) obj;
        }
        if (obj != null) {
            return new DSTU4145PublicKey(ASN1OctetString.getInstance(obj));
        }
        return null;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.pubKey;
    }
}
