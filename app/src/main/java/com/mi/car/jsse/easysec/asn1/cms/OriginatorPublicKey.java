//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class OriginatorPublicKey extends ASN1Object {
    private AlgorithmIdentifier algorithm;
    private DERBitString publicKey;

    public OriginatorPublicKey(AlgorithmIdentifier algorithm, byte[] publicKey) {
        this.algorithm = algorithm;
        this.publicKey = new DERBitString(publicKey);
    }

    private OriginatorPublicKey(ASN1Sequence seq) {
        this.algorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.publicKey = (DERBitString)seq.getObjectAt(1);
    }

    public static OriginatorPublicKey getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OriginatorPublicKey getInstance(Object obj) {
        if (obj instanceof OriginatorPublicKey) {
            return (OriginatorPublicKey)obj;
        } else {
            return obj != null ? new OriginatorPublicKey(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public AlgorithmIdentifier getAlgorithm() {
        return this.algorithm;
    }

    public DERBitString getPublicKey() {
        return this.publicKey;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.algorithm);
        v.add(this.publicKey);
        return new DERSequence(v);
    }
}
