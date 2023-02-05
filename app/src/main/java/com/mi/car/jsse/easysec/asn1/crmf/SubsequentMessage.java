package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1Integer;

public class SubsequentMessage extends ASN1Integer {
    public static final SubsequentMessage challengeResp = new SubsequentMessage(1);
    public static final SubsequentMessage encrCert = new SubsequentMessage(0);

    private SubsequentMessage(int value) {
        super((long) value);
    }

    public static SubsequentMessage valueOf(int value) {
        if (value == 0) {
            return encrCert;
        }
        if (value == 1) {
            return challengeResp;
        }
        throw new IllegalArgumentException("unknown value: " + value);
    }
}
