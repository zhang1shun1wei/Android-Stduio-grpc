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
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class KeyTransRecipientInfo extends ASN1Object {
    private ASN1Integer version;
    private RecipientIdentifier rid;
    private AlgorithmIdentifier keyEncryptionAlgorithm;
    private ASN1OctetString encryptedKey;

    public KeyTransRecipientInfo(RecipientIdentifier rid, AlgorithmIdentifier keyEncryptionAlgorithm, ASN1OctetString encryptedKey) {
        if (rid.toASN1Primitive() instanceof ASN1TaggedObject) {
            this.version = new ASN1Integer(2L);
        } else {
            this.version = new ASN1Integer(0L);
        }

        this.rid = rid;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.encryptedKey = encryptedKey;
    }

    private KeyTransRecipientInfo(ASN1Sequence seq) {
        this.version = (ASN1Integer)seq.getObjectAt(0);
        this.rid = RecipientIdentifier.getInstance(seq.getObjectAt(1));
        this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
        this.encryptedKey = (ASN1OctetString)seq.getObjectAt(3);
    }

    public static KeyTransRecipientInfo getInstance(Object obj) {
        if (obj instanceof KeyTransRecipientInfo) {
            return (KeyTransRecipientInfo)obj;
        } else {
            return obj != null ? new KeyTransRecipientInfo(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public RecipientIdentifier getRecipientIdentifier() {
        return this.rid;
    }

    public AlgorithmIdentifier getKeyEncryptionAlgorithm() {
        return this.keyEncryptionAlgorithm;
    }

    public ASN1OctetString getEncryptedKey() {
        return this.encryptedKey;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.version);
        v.add(this.rid);
        v.add(this.keyEncryptionAlgorithm);
        v.add(this.encryptedKey);
        return new DERSequence(v);
    }
}
