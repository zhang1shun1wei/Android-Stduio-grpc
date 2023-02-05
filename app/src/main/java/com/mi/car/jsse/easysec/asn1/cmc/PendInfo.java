//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;

public class PendInfo extends ASN1Object {
    private final byte[] pendToken;
    private final ASN1GeneralizedTime pendTime;

    public PendInfo(byte[] pendToken, ASN1GeneralizedTime pendTime) {
        this.pendToken = Arrays.clone(pendToken);
        this.pendTime = pendTime;
    }

    private PendInfo(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.pendToken = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
            this.pendTime = ASN1GeneralizedTime.getInstance(seq.getObjectAt(1));
        }
    }

    public static PendInfo getInstance(Object o) {
        if (o instanceof PendInfo) {
            return (PendInfo)o;
        } else {
            return o != null ? new PendInfo(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(new DEROctetString(this.pendToken));
        v.add(this.pendTime);
        return new DERSequence(v);
    }

    public byte[] getPendToken() {
        return Arrays.clone(this.pendToken);
    }

    public ASN1GeneralizedTime getPendTime() {
        return this.pendTime;
    }
}