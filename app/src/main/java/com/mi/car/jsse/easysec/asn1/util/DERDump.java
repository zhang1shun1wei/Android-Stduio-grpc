package com.mi.car.jsse.easysec.asn1.util;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;

public class DERDump extends ASN1Dump {
    public static String dumpAsString(ASN1Primitive obj) {
        StringBuffer buf = new StringBuffer();
        _dumpAsString("", false, obj, buf);
        return buf.toString();
    }

    public static String dumpAsString(ASN1Encodable obj) {
        return dumpAsString(obj.toASN1Primitive());
    }
}
