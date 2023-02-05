//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class KeyAgreeRecipientInfo extends ASN1Object {
    private ASN1Integer version;
    private OriginatorIdentifierOrKey originator;
    private ASN1OctetString ukm;
    private AlgorithmIdentifier keyEncryptionAlgorithm;
    private ASN1Sequence recipientEncryptedKeys;

    public KeyAgreeRecipientInfo(OriginatorIdentifierOrKey originator, ASN1OctetString ukm, AlgorithmIdentifier keyEncryptionAlgorithm, ASN1Sequence recipientEncryptedKeys) {
        this.version = new ASN1Integer(3L);
        this.originator = originator;
        this.ukm = ukm;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.recipientEncryptedKeys = recipientEncryptedKeys;
    }

    private KeyAgreeRecipientInfo(ASN1Sequence seq) {
        int index = 0;
        index = index + 1;
        this.version = (ASN1Integer)seq.getObjectAt(index);
        this.originator = OriginatorIdentifierOrKey.getInstance((ASN1TaggedObject)seq.getObjectAt(index++), true);
        if (seq.getObjectAt(index) instanceof ASN1TaggedObject) {
            this.ukm = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(index++), true);
        }

        this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));
        this.recipientEncryptedKeys = (ASN1Sequence)seq.getObjectAt(index++);
    }

    public static KeyAgreeRecipientInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static KeyAgreeRecipientInfo getInstance(Object obj) {
        if (obj instanceof KeyAgreeRecipientInfo) {
            return (KeyAgreeRecipientInfo)obj;
        } else {
            return obj != null ? new KeyAgreeRecipientInfo(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public OriginatorIdentifierOrKey getOriginator() {
        return this.originator;
    }

    public ASN1OctetString getUserKeyingMaterial() {
        return this.ukm;
    }

    public AlgorithmIdentifier getKeyEncryptionAlgorithm() {
        return this.keyEncryptionAlgorithm;
    }

    public ASN1Sequence getRecipientEncryptedKeys() {
        return this.recipientEncryptedKeys;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(5);
        v.add(this.version);
        v.add(new DERTaggedObject(true, 0, this.originator));
        if (this.ukm != null) {
            v.add(new DERTaggedObject(true, 1, this.ukm));
        }

        v.add(this.keyEncryptionAlgorithm);
        v.add(this.recipientEncryptedKeys);
        return new DERSequence(v);
    }
}
