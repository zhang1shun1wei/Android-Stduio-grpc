//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.math.BigInteger;

public class PollReqContent extends ASN1Object {
    private final ASN1Sequence content;

    private PollReqContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public PollReqContent(ASN1Integer certReqId) {
        this((ASN1Sequence)(new DERSequence(new DERSequence(certReqId))));
    }

    public PollReqContent(ASN1Integer[] certReqIds) {
        this((ASN1Sequence)(new DERSequence(intsToSequence(certReqIds))));
    }

    public PollReqContent(BigInteger certReqId) {
        this(new ASN1Integer(certReqId));
    }

    public PollReqContent(BigInteger[] certReqIds) {
        this(intsToASN1(certReqIds));
    }

    public static PollReqContent getInstance(Object o) {
        if (o instanceof PollReqContent) {
            return (PollReqContent)o;
        } else {
            return o != null ? new PollReqContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    private static ASN1Integer[] sequenceToASN1IntegerArray(ASN1Sequence seq) {
        ASN1Integer[] result = new ASN1Integer[seq.size()];

        for(int i = 0; i != result.length; ++i) {
            result[i] = ASN1Integer.getInstance(seq.getObjectAt(i));
        }

        return result;
    }

    private static DERSequence[] intsToSequence(ASN1Integer[] ids) {
        DERSequence[] result = new DERSequence[ids.length];

        for(int i = 0; i != result.length; ++i) {
            result[i] = new DERSequence(ids[i]);
        }

        return result;
    }

    private static ASN1Integer[] intsToASN1(BigInteger[] ids) {
        ASN1Integer[] result = new ASN1Integer[ids.length];

        for(int i = 0; i != result.length; ++i) {
            result[i] = new ASN1Integer(ids[i]);
        }

        return result;
    }

    public ASN1Integer[][] getCertReqIds() {
        ASN1Integer[][] result = new ASN1Integer[this.content.size()][];

        for(int i = 0; i != result.length; ++i) {
            result[i] = sequenceToASN1IntegerArray((ASN1Sequence)this.content.getObjectAt(i));
        }

        return result;
    }

    public BigInteger[] getCertReqIdValues() {
        BigInteger[] result = new BigInteger[this.content.size()];

        for(int i = 0; i != result.length; ++i) {
            result[i] = ASN1Integer.getInstance(ASN1Sequence.getInstance(this.content.getObjectAt(i)).getObjectAt(0)).getValue();
        }

        return result;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.content;
    }
}
