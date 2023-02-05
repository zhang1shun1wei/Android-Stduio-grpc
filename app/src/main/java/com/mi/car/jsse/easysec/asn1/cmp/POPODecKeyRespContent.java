//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;

public class POPODecKeyRespContent extends ASN1Object {
    private final ASN1Sequence content;

    private POPODecKeyRespContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public static POPODecKeyRespContent getInstance(Object o) {
        if (o instanceof POPODecKeyRespContent) {
            return (POPODecKeyRespContent)o;
        } else {
            return o != null ? new POPODecKeyRespContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ASN1Integer[] toASN1IntegerArray() {
        ASN1Integer[] result = new ASN1Integer[this.content.size()];

        for(int i = 0; i != result.length; ++i) {
            result[i] = ASN1Integer.getInstance(this.content.getObjectAt(i));
        }

        return result;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.content;
    }
}
