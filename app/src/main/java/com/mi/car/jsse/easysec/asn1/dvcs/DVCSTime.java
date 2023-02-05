package com.mi.car.jsse.easysec.asn1.dvcs;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.cms.ContentInfo;
import java.util.Date;

public class DVCSTime extends ASN1Object implements ASN1Choice {
    private final ASN1GeneralizedTime genTime;
    private final ContentInfo timeStampToken;

    public DVCSTime(Date time) {
        this(new ASN1GeneralizedTime(time));
    }

    public DVCSTime(ASN1GeneralizedTime genTime2) {
        this.genTime = genTime2;
        this.timeStampToken = null;
    }

    public DVCSTime(ContentInfo timeStampToken2) {
        this.genTime = null;
        this.timeStampToken = timeStampToken2;
    }

    public static DVCSTime getInstance(Object obj) {
        if (obj instanceof DVCSTime) {
            return (DVCSTime) obj;
        }
        if (obj instanceof ASN1GeneralizedTime) {
            return new DVCSTime(ASN1GeneralizedTime.getInstance(obj));
        }
        if (obj != null) {
            return new DVCSTime(ContentInfo.getInstance(obj));
        }
        return null;
    }

    public static DVCSTime getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(obj.getObject());
    }

    public ASN1GeneralizedTime getGenTime() {
        return this.genTime;
    }

    public ContentInfo getTimeStampToken() {
        return this.timeStampToken;
    }

    public ASN1Primitive toASN1Primitive() {
        if (this.genTime != null) {
            return this.genTime;
        }
        return this.timeStampToken.toASN1Primitive();
    }

    public String toString() {
        if (this.genTime != null) {
            return this.genTime.toString();
        }
        return this.timeStampToken.toString();
    }
}
