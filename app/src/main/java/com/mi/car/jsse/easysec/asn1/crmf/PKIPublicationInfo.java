package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.math.BigInteger;

public class PKIPublicationInfo extends ASN1Object {
    public static final ASN1Integer dontPublish = new ASN1Integer(0);
    public static final ASN1Integer pleasePublish = new ASN1Integer(1);
    private ASN1Integer action;
    private ASN1Sequence pubInfos;

    private PKIPublicationInfo(ASN1Sequence seq) {
        this.action = ASN1Integer.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.pubInfos = ASN1Sequence.getInstance(seq.getObjectAt(1));
        }
    }

    public static PKIPublicationInfo getInstance(Object o) {
        if (o instanceof PKIPublicationInfo) {
            return (PKIPublicationInfo) o;
        }
        if (o != null) {
            return new PKIPublicationInfo(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public PKIPublicationInfo(BigInteger action2) {
        this(new ASN1Integer(action2));
    }

    public PKIPublicationInfo(ASN1Integer action2) {
        this.action = action2;
    }

    /* JADX INFO: this call moved to the top of the method (can break code semantics) */
    public PKIPublicationInfo(SinglePubInfo pubInfo) {
        this(pubInfo != null ? new SinglePubInfo[]{pubInfo} : null);
    }

    public PKIPublicationInfo(SinglePubInfo[] pubInfos2) {
        this.action = pleasePublish;
        if (pubInfos2 != null) {
            this.pubInfos = new DERSequence(pubInfos2);
        } else {
            this.pubInfos = null;
        }
    }

    public ASN1Integer getAction() {
        return this.action;
    }

    public SinglePubInfo[] getPubInfos() {
        if (this.pubInfos == null) {
            return null;
        }
        SinglePubInfo[] results = new SinglePubInfo[this.pubInfos.size()];
        for (int i = 0; i != results.length; i++) {
            results[i] = SinglePubInfo.getInstance(this.pubInfos.getObjectAt(i));
        }
        return results;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.action);
        if (this.pubInfos != null) {
            v.add(this.pubInfos);
        }
        return new DERSequence(v);
    }
}
