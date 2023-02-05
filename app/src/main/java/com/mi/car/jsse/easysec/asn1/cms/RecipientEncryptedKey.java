//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class RecipientEncryptedKey extends ASN1Object {
    private KeyAgreeRecipientIdentifier identifier;
    private ASN1OctetString encryptedKey;

    private RecipientEncryptedKey(ASN1Sequence seq) {
        this.identifier = KeyAgreeRecipientIdentifier.getInstance(seq.getObjectAt(0));
        this.encryptedKey = (ASN1OctetString)seq.getObjectAt(1);
    }

    public static RecipientEncryptedKey getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RecipientEncryptedKey getInstance(Object obj) {
        if (obj instanceof RecipientEncryptedKey) {
            return (RecipientEncryptedKey)obj;
        } else {
            return obj != null ? new RecipientEncryptedKey(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public RecipientEncryptedKey(KeyAgreeRecipientIdentifier id, ASN1OctetString encryptedKey) {
        this.identifier = id;
        this.encryptedKey = encryptedKey;
    }

    public KeyAgreeRecipientIdentifier getIdentifier() {
        return this.identifier;
    }

    public ASN1OctetString getEncryptedKey() {
        return this.encryptedKey;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.identifier);
        v.add(this.encryptedKey);
        return new DERSequence(v);
    }
}
