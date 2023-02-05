//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class PKIMessages extends ASN1Object {
    private final ASN1Sequence content;

    private PKIMessages(ASN1Sequence seq) {
        this.content = seq;
    }

    public PKIMessages(PKIMessage msg) {
        this.content = new DERSequence(msg);
    }

    public PKIMessages(PKIMessage[] msgs) {
        this.content = new DERSequence(msgs);
    }

    public static PKIMessages getInstance(Object o) {
        if (o instanceof PKIMessages) {
            return (PKIMessages)o;
        } else {
            return o != null ? new PKIMessages(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public PKIMessage[] toPKIMessageArray() {
        PKIMessage[] result = new PKIMessage[this.content.size()];

        for(int i = 0; i != result.length; ++i) {
            result[i] = PKIMessage.getInstance(this.content.getObjectAt(i));
        }

        return result;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.content;
    }
}
