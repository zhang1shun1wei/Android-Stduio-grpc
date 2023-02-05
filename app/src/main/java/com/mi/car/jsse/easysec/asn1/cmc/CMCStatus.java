//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import java.util.HashMap;
import java.util.Map;

public class CMCStatus extends ASN1Object {
    public static final CMCStatus success = new CMCStatus(new ASN1Integer(0L));
    public static final CMCStatus failed = new CMCStatus(new ASN1Integer(2L));
    public static final CMCStatus pending = new CMCStatus(new ASN1Integer(3L));
    public static final CMCStatus noSupport = new CMCStatus(new ASN1Integer(4L));
    public static final CMCStatus confirmRequired = new CMCStatus(new ASN1Integer(5L));
    public static final CMCStatus popRequired = new CMCStatus(new ASN1Integer(6L));
    public static final CMCStatus partial = new CMCStatus(new ASN1Integer(7L));
    private static Map range = new HashMap();
    private final ASN1Integer value;

    private CMCStatus(ASN1Integer value) {
        this.value = value;
    }

    public static CMCStatus getInstance(Object o) {
        if (o instanceof CMCStatus) {
            return (CMCStatus)o;
        } else if (o != null) {
            CMCStatus status = (CMCStatus)range.get(ASN1Integer.getInstance(o));
            if (status != null) {
                return status;
            } else {
                throw new IllegalArgumentException("unknown object in getInstance(): " + o.getClass().getName());
            }
        } else {
            return null;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        return this.value;
    }

    static {
        range.put(success.value, success);
        range.put(failed.value, failed);
        range.put(pending.value, pending);
        range.put(noSupport.value, noSupport);
        range.put(confirmRequired.value, confirmRequired);
        range.put(popRequired.value, popRequired);
        range.put(partial.value, partial);
    }
}