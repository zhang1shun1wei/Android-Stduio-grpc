package com.mi.car.jsse.easysec.asn1.tsp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DLSequence;

public class EncryptionInfo extends ASN1Object {
    private ASN1ObjectIdentifier encryptionInfoType;
    private ASN1Encodable encryptionInfoValue;

    public static EncryptionInfo getInstance(ASN1Object obj) {
        if (obj instanceof EncryptionInfo) {
            return (EncryptionInfo) obj;
        }
        if (obj != null) {
            return new EncryptionInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static EncryptionInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    private EncryptionInfo(ASN1Sequence sequence) {
        if (sequence.size() != 2) {
            throw new IllegalArgumentException("wrong sequence size in constructor: " + sequence.size());
        }
        this.encryptionInfoType = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
        this.encryptionInfoValue = sequence.getObjectAt(1);
    }

    public EncryptionInfo(ASN1ObjectIdentifier encryptionInfoType2, ASN1Encodable encryptionInfoValue2) {
        this.encryptionInfoType = encryptionInfoType2;
        this.encryptionInfoValue = encryptionInfoValue2;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.encryptionInfoType);
        v.add(this.encryptionInfoValue);
        return new DLSequence(v);
    }
}
