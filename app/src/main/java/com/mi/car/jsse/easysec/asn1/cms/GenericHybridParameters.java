//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class GenericHybridParameters extends ASN1Object {
    private final AlgorithmIdentifier kem;
    private final AlgorithmIdentifier dem;

    private GenericHybridParameters(ASN1Sequence sequence) {
        if (sequence.size() != 2) {
            throw new IllegalArgumentException("ASN.1 SEQUENCE should be of length 2");
        } else {
            this.kem = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
            this.dem = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
        }
    }

    public static GenericHybridParameters getInstance(Object o) {
        if (o instanceof GenericHybridParameters) {
            return (GenericHybridParameters)o;
        } else {
            return o != null ? new GenericHybridParameters(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public GenericHybridParameters(AlgorithmIdentifier kem, AlgorithmIdentifier dem) {
        this.kem = kem;
        this.dem = dem;
    }

    public AlgorithmIdentifier getDem() {
        return this.dem;
    }

    public AlgorithmIdentifier getKem() {
        return this.kem;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.kem);
        v.add(this.dem);
        return new DERSequence(v);
    }
}
