//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;

public class GCMParameters extends ASN1Object {
    private byte[] nonce;
    private int icvLen;

    public static GCMParameters getInstance(Object obj) {
        if (obj instanceof GCMParameters) {
            return (GCMParameters)obj;
        } else {
            return obj != null ? new GCMParameters(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    private GCMParameters(ASN1Sequence seq) {
        this.nonce = ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets();
        if (seq.size() == 2) {
            this.icvLen = ASN1Integer.getInstance(seq.getObjectAt(1)).intValueExact();
        } else {
            this.icvLen = 12;
        }

    }

    public GCMParameters(byte[] nonce, int icvLen) {
        this.nonce = Arrays.clone(nonce);
        this.icvLen = icvLen;
    }

    public byte[] getNonce() {
        return Arrays.clone(this.nonce);
    }

    public int getIcvLen() {
        return this.icvLen;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(new DEROctetString(this.nonce));
        if (this.icvLen != 12) {
            v.add(new ASN1Integer((long)this.icvLen));
        }

        return new DERSequence(v);
    }
}
