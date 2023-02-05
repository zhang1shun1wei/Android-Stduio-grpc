//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class DHBMParameter extends ASN1Object {
    private final AlgorithmIdentifier owf;
    private final AlgorithmIdentifier mac;

    private DHBMParameter(ASN1Sequence sequence) {
        if (sequence.size() != 2) {
            throw new IllegalArgumentException("expecting sequence size of 2");
        } else {
            this.owf = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
            this.mac = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
        }
    }

    public DHBMParameter(AlgorithmIdentifier owf, AlgorithmIdentifier mac) {
        this.owf = owf;
        this.mac = mac;
    }

    public static DHBMParameter getInstance(Object o) {
        if (o instanceof DHBMParameter) {
            return (DHBMParameter)o;
        } else {
            return o != null ? new DHBMParameter(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public AlgorithmIdentifier getOwf() {
        return this.owf;
    }

    public AlgorithmIdentifier getMac() {
        return this.mac;
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{this.owf, this.mac});
    }
}
