//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;

public class CertConfirmContent extends ASN1Object {
    private final ASN1Sequence content;

    private CertConfirmContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public static CertConfirmContent getInstance(Object o) {
        if (o instanceof CertConfirmContent) {
            return (CertConfirmContent)o;
        } else {
            return o != null ? new CertConfirmContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public CertStatus[] toCertStatusArray() {
        CertStatus[] result = new CertStatus[this.content.size()];

        for(int i = 0; i != result.length; ++i) {
            result[i] = CertStatus.getInstance(this.content.getObjectAt(i));
        }

        return result;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.content;
    }
}
