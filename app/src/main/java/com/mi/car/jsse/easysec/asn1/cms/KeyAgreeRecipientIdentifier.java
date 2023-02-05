//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class KeyAgreeRecipientIdentifier extends ASN1Object implements ASN1Choice {
    private IssuerAndSerialNumber issuerSerial;
    private RecipientKeyIdentifier rKeyID;

    public static KeyAgreeRecipientIdentifier getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static KeyAgreeRecipientIdentifier getInstance(Object obj) {
        if (obj != null && !(obj instanceof KeyAgreeRecipientIdentifier)) {
            if (obj instanceof ASN1Sequence) {
                return new KeyAgreeRecipientIdentifier(IssuerAndSerialNumber.getInstance(obj));
            } else if (obj instanceof ASN1TaggedObject && ((ASN1TaggedObject)obj).getTagNo() == 0) {
                return new KeyAgreeRecipientIdentifier(RecipientKeyIdentifier.getInstance((ASN1TaggedObject)obj, false));
            } else {
                throw new IllegalArgumentException("Invalid KeyAgreeRecipientIdentifier: " + obj.getClass().getName());
            }
        } else {
            return (KeyAgreeRecipientIdentifier)obj;
        }
    }

    public KeyAgreeRecipientIdentifier(IssuerAndSerialNumber issuerSerial) {
        this.issuerSerial = issuerSerial;
        this.rKeyID = null;
    }

    public KeyAgreeRecipientIdentifier(RecipientKeyIdentifier rKeyID) {
        this.issuerSerial = null;
        this.rKeyID = rKeyID;
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber() {
        return this.issuerSerial;
    }

    public RecipientKeyIdentifier getRKeyID() {
        return this.rKeyID;
    }

    public ASN1Primitive toASN1Primitive() {
        return (ASN1Primitive)(this.issuerSerial != null ? this.issuerSerial.toASN1Primitive() : new DERTaggedObject(false, 0, this.rKeyID));
    }
}
