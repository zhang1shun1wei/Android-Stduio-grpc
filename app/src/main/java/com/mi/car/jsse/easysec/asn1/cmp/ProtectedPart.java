//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class ProtectedPart extends ASN1Object {
    private final PKIHeader header;
    private final PKIBody body;

    private ProtectedPart(ASN1Sequence seq) {
        this.header = PKIHeader.getInstance(seq.getObjectAt(0));
        this.body = PKIBody.getInstance(seq.getObjectAt(1));
    }

    public ProtectedPart(PKIHeader header, PKIBody body) {
        this.header = header;
        this.body = body;
    }

    public static ProtectedPart getInstance(Object o) {
        if (o instanceof ProtectedPart) {
            return (ProtectedPart)o;
        } else {
            return o != null ? new ProtectedPart(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public PKIHeader getHeader() {
        return this.header;
    }

    public PKIBody getBody() {
        return this.body;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.header);
        v.add(this.body);
        return new DERSequence(v);
    }
}
