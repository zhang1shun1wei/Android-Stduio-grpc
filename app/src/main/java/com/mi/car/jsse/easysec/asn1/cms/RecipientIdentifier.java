//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class RecipientIdentifier extends ASN1Object implements ASN1Choice {
    private ASN1Encodable id;

    public RecipientIdentifier(IssuerAndSerialNumber id) {
        this.id = id;
    }

    public RecipientIdentifier(ASN1OctetString id) {
        this.id = new DERTaggedObject(false, 0, id);
    }

    public RecipientIdentifier(ASN1Primitive id) {
        this.id = id;
    }

    public static RecipientIdentifier getInstance(Object o) {
        if (o != null && !(o instanceof RecipientIdentifier)) {
            if (o instanceof IssuerAndSerialNumber) {
                return new RecipientIdentifier((IssuerAndSerialNumber)o);
            } else if (o instanceof ASN1OctetString) {
                return new RecipientIdentifier((ASN1OctetString)o);
            } else if (o instanceof ASN1Primitive) {
                return new RecipientIdentifier((ASN1Primitive)o);
            } else {
                throw new IllegalArgumentException("Illegal object in RecipientIdentifier: " + o.getClass().getName());
            }
        } else {
            return (RecipientIdentifier)o;
        }
    }

    public boolean isTagged() {
        return this.id instanceof ASN1TaggedObject;
    }

    public ASN1Encodable getId() {
        return (ASN1Encodable)(this.id instanceof ASN1TaggedObject ? ASN1OctetString.getInstance((ASN1TaggedObject)this.id, false) : IssuerAndSerialNumber.getInstance(this.id));
    }

    public ASN1Primitive toASN1Primitive() {
        return this.id.toASN1Primitive();
    }
}
