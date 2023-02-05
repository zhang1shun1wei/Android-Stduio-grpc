package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class CertReqMessages extends ASN1Object {
    private ASN1Sequence content;

    private CertReqMessages(ASN1Sequence seq) {
        this.content = seq;
    }

    public static CertReqMessages getInstance(Object o) {
        if (o instanceof CertReqMessages) {
            return (CertReqMessages) o;
        }
        if (o != null) {
            return new CertReqMessages(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public CertReqMessages(CertReqMsg msg) {
        this.content = new DERSequence(msg);
    }

    public CertReqMessages(CertReqMsg[] msgs) {
        this.content = new DERSequence(msgs);
    }

    public CertReqMsg[] toCertReqMsgArray() {
        CertReqMsg[] result = new CertReqMsg[this.content.size()];
        for (int i = 0; i != result.length; i++) {
            result[i] = CertReqMsg.getInstance(this.content.getObjectAt(i));
        }
        return result;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.content;
    }
}
