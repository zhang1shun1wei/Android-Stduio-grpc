//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class RevReqContent extends ASN1Object {
    private final ASN1Sequence content;

    private RevReqContent(ASN1Sequence seq) {
        this.content = seq;
    }

    public RevReqContent(RevDetails revDetails) {
        this.content = new DERSequence(revDetails);
    }

    public RevReqContent(RevDetails[] revDetailsArray) {
        this.content = new DERSequence(revDetailsArray);
    }

    public static RevReqContent getInstance(Object o) {
        if (o instanceof RevReqContent) {
            return (RevReqContent)o;
        } else {
            return o != null ? new RevReqContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public RevDetails[] toRevDetailsArray() {
        RevDetails[] result = new RevDetails[this.content.size()];

        for(int i = 0; i != result.length; ++i) {
            result[i] = RevDetails.getInstance(this.content.getObjectAt(i));
        }

        return result;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.content;
    }
}
