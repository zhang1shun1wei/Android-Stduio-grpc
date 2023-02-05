package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;

public class CertPolicyId extends ASN1Object {
    private ASN1ObjectIdentifier id;

    private CertPolicyId(ASN1ObjectIdentifier id2) {
        this.id = id2;
    }

    public static CertPolicyId getInstance(Object o) {
        if (o instanceof CertPolicyId) {
            return (CertPolicyId) o;
        }
        if (o != null) {
            return new CertPolicyId(ASN1ObjectIdentifier.getInstance(o));
        }
        return null;
    }

    public String getId() {
        return this.id.getId();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.id;
    }
}
