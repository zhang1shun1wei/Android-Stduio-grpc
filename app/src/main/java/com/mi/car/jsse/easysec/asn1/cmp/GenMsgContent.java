//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class GenMsgContent extends ASN1Object {
    private final ASN1Sequence content;

    private GenMsgContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public GenMsgContent(InfoTypeAndValue itv) {
        this.content = new DERSequence(itv);
    }

    public GenMsgContent(InfoTypeAndValue[] itvs) {
        this.content = new DERSequence(itvs);
    }

    public static GenMsgContent getInstance(Object o) {
        if (o instanceof GenMsgContent) {
            return (GenMsgContent)o;
        } else {
            return o != null ? new GenMsgContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public InfoTypeAndValue[] toInfoTypeAndValueArray() {
        InfoTypeAndValue[] result = new InfoTypeAndValue[this.content.size()];

        for(int i = 0; i != result.length; ++i) {
            result[i] = InfoTypeAndValue.getInstance(this.content.getObjectAt(i));
        }

        return result;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.content;
    }
}
