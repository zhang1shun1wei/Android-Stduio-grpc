package com.mi.car.jsse.easysec.asn1.tsp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.cmp.PKIStatusInfo;
import com.mi.car.jsse.easysec.asn1.cms.ContentInfo;
import java.util.Enumeration;

public class TimeStampResp extends ASN1Object {
    PKIStatusInfo pkiStatusInfo;
    ContentInfo timeStampToken;

    public static TimeStampResp getInstance(Object o) {
        if (o instanceof TimeStampResp) {
            return (TimeStampResp) o;
        }
        if (o != null) {
            return new TimeStampResp(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    private TimeStampResp(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.pkiStatusInfo = PKIStatusInfo.getInstance(e.nextElement());
        if (e.hasMoreElements()) {
            this.timeStampToken = ContentInfo.getInstance(e.nextElement());
        }
    }

    public TimeStampResp(PKIStatusInfo pkiStatusInfo2, ContentInfo timeStampToken2) {
        this.pkiStatusInfo = pkiStatusInfo2;
        this.timeStampToken = timeStampToken2;
    }

    public PKIStatusInfo getStatus() {
        return this.pkiStatusInfo;
    }

    public ContentInfo getTimeStampToken() {
        return this.timeStampToken;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.pkiStatusInfo);
        if (this.timeStampToken != null) {
            v.add(this.timeStampToken);
        }
        return new DERSequence(v);
    }
}
