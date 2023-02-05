package com.mi.car.jsse.easysec.asn1.x9;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;

public class KeySpecificInfo extends ASN1Object {
    private ASN1ObjectIdentifier algorithm;
    private ASN1OctetString counter;

    public KeySpecificInfo(ASN1ObjectIdentifier algorithm2, ASN1OctetString counter2) {
        this.algorithm = algorithm2;
        this.counter = counter2;
    }

    public static KeySpecificInfo getInstance(Object obj) {
        if (obj instanceof KeySpecificInfo) {
            return (KeySpecificInfo) obj;
        }
        if (obj != null) {
            return new KeySpecificInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private KeySpecificInfo(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.algorithm = (ASN1ObjectIdentifier) e.nextElement();
        this.counter = (ASN1OctetString) e.nextElement();
    }

    public ASN1ObjectIdentifier getAlgorithm() {
        return this.algorithm;
    }

    public ASN1OctetString getCounter() {
        return this.counter;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.algorithm);
        v.add(this.counter);
        return new DERSequence(v);
    }
}
