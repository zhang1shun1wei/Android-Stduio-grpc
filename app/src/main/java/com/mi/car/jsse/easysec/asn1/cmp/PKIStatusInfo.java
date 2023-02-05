//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.math.BigInteger;

public class PKIStatusInfo extends ASN1Object {
    ASN1Integer status;
    PKIFreeText statusString;
    ASN1BitString failInfo;

    private PKIStatusInfo(ASN1Sequence seq) {
        this.status = ASN1Integer.getInstance(seq.getObjectAt(0));
        this.statusString = null;
        this.failInfo = null;
        if (seq.size() > 2) {
            this.statusString = PKIFreeText.getInstance(seq.getObjectAt(1));
            this.failInfo = DERBitString.getInstance(seq.getObjectAt(2));
        } else if (seq.size() > 1) {
            Object obj = seq.getObjectAt(1);
            if (obj instanceof ASN1BitString) {
                this.failInfo = ASN1BitString.getInstance(obj);
            } else {
                this.statusString = PKIFreeText.getInstance(obj);
            }
        }

    }

    public PKIStatusInfo(PKIStatus status) {
        this.status = ASN1Integer.getInstance(status.toASN1Primitive());
    }

    public PKIStatusInfo(PKIStatus status, PKIFreeText statusString) {
        this.status = ASN1Integer.getInstance(status.toASN1Primitive());
        this.statusString = statusString;
    }

    public PKIStatusInfo(PKIStatus status, PKIFreeText statusString, PKIFailureInfo failInfo) {
        this.status = ASN1Integer.getInstance(status.toASN1Primitive());
        this.statusString = statusString;
        this.failInfo = failInfo;
    }

    public static PKIStatusInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static PKIStatusInfo getInstance(Object obj) {
        if (obj instanceof PKIStatusInfo) {
            return (PKIStatusInfo)obj;
        } else {
            return obj != null ? new PKIStatusInfo(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public BigInteger getStatus() {
        return this.status.getValue();
    }

    public PKIFreeText getStatusString() {
        return this.statusString;
    }

    public ASN1BitString getFailInfo() {
        return this.failInfo;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.status);
        if (this.statusString != null) {
            v.add(this.statusString);
        }

        if (this.failInfo != null) {
            v.add(this.failInfo);
        }

        return new DERSequence(v);
    }
}
