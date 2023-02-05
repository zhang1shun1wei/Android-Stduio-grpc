//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.ASN1UTCTime;
import com.mi.car.jsse.easysec.asn1.DERGeneralizedTime;
import com.mi.car.jsse.easysec.asn1.DERUTCTime;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;

public class Time extends ASN1Object implements ASN1Choice {
    ASN1Primitive time;

    public static Time getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(obj.getObject());
    }

    private Time(ASN1Primitive time) {
        if (!(time instanceof ASN1UTCTime) && !(time instanceof ASN1GeneralizedTime)) {
            throw new IllegalArgumentException("unknown object passed to Time");
        } else {
            this.time = time;
        }
    }

    public Time(Date time) {
        SimpleTimeZone tz = new SimpleTimeZone(0, "Z");
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss");
        dateF.setTimeZone(tz);
        String d = dateF.format(time) + "Z";
        int year = Integer.parseInt(d.substring(0, 4));
        if (year >= 1950 && year <= 2049) {
            this.time = new DERUTCTime(d.substring(2));
        } else {
            this.time = new DERGeneralizedTime(d);
        }

    }

    public Time(Date time, Locale locale) {
        SimpleTimeZone tz = new SimpleTimeZone(0, "Z");
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss", locale);
        dateF.setTimeZone(tz);
        String d = dateF.format(time) + "Z";
        int year = Integer.parseInt(d.substring(0, 4));
        if (year >= 1950 && year <= 2049) {
            this.time = new DERUTCTime(d.substring(2));
        } else {
            this.time = new DERGeneralizedTime(d);
        }

    }

    public static Time getInstance(Object obj) {
        if (obj != null && !(obj instanceof Time)) {
            if (obj instanceof ASN1UTCTime) {
                return new Time((ASN1UTCTime)obj);
            } else if (obj instanceof ASN1GeneralizedTime) {
                return new Time((ASN1GeneralizedTime)obj);
            } else {
                throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
            }
        } else {
            return (Time)obj;
        }
    }

    public String getTime() {
        return this.time instanceof ASN1UTCTime ? ((ASN1UTCTime)this.time).getAdjustedTime() : ((ASN1GeneralizedTime)this.time).getTime();
    }

    public Date getDate() {
        try {
            return this.time instanceof ASN1UTCTime ? ((ASN1UTCTime)this.time).getAdjustedDate() : ((ASN1GeneralizedTime)this.time).getDate();
        } catch (ParseException var2) {
            throw new IllegalStateException("invalid date string: " + var2.getMessage());
        }
    }

    public ASN1Primitive toASN1Primitive() {
        return this.time;
    }
}
