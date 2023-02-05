package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.cms.EnvelopedData;

public class EncryptedKey extends ASN1Object implements ASN1Choice {
    private EncryptedValue encryptedValue;
    private EnvelopedData envelopedData;

    public static EncryptedKey getInstance(Object o) {
        if (o instanceof EncryptedKey) {
            return (EncryptedKey) o;
        }
        if (o instanceof ASN1TaggedObject) {
            return new EncryptedKey(EnvelopedData.getInstance((ASN1TaggedObject) o, false));
        }
        if (o instanceof EncryptedValue) {
            return new EncryptedKey((EncryptedValue) o);
        }
        return new EncryptedKey(EncryptedValue.getInstance(o));
    }

    public EncryptedKey(EnvelopedData envelopedData2) {
        this.envelopedData = envelopedData2;
    }

    public EncryptedKey(EncryptedValue encryptedValue2) {
        this.encryptedValue = encryptedValue2;
    }

    public boolean isEncryptedValue() {
        return this.encryptedValue != null;
    }

    public ASN1Encodable getValue() {
        if (this.encryptedValue != null) {
            return this.encryptedValue;
        }
        return this.envelopedData;
    }

    public ASN1Primitive toASN1Primitive() {
        if (this.encryptedValue != null) {
            return this.encryptedValue.toASN1Primitive();
        }
        return new DERTaggedObject(false, 0, this.envelopedData);
    }
}
