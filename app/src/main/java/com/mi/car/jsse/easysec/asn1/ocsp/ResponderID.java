package com.mi.car.jsse.easysec.asn1.ocsp;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;

public class ResponderID extends ASN1Object implements ASN1Choice {
    private ASN1Encodable value;

    public ResponderID(ASN1OctetString value2) {
        this.value = value2;
    }

    public ResponderID(X500Name value2) {
        this.value = value2;
    }

    public static ResponderID getInstance(Object obj) {
        if (obj instanceof ResponderID) {
            return (ResponderID) obj;
        }
        if (obj instanceof DEROctetString) {
            return new ResponderID((DEROctetString) obj);
        }
        if (!(obj instanceof ASN1TaggedObject)) {
            return new ResponderID(X500Name.getInstance(obj));
        }
        ASN1TaggedObject o = (ASN1TaggedObject) obj;
        if (o.getTagNo() == 1) {
            return new ResponderID(X500Name.getInstance(o, true));
        }
        return new ResponderID(ASN1OctetString.getInstance(o, true));
    }

    public static ResponderID getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(obj.getObject());
    }

    public byte[] getKeyHash() {
        if (this.value instanceof ASN1OctetString) {
            return ((ASN1OctetString) this.value).getOctets();
        }
        return null;
    }

    public X500Name getName() {
        if (this.value instanceof ASN1OctetString) {
            return null;
        }
        return X500Name.getInstance(this.value);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        if (this.value instanceof ASN1OctetString) {
            return new DERTaggedObject(true, 2, this.value);
        }
        return new DERTaggedObject(true, 1, this.value);
    }
}
