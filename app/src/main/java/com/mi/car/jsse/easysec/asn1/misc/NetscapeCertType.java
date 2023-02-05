package com.mi.car.jsse.easysec.asn1.misc;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.DERBitString;

public class NetscapeCertType extends DERBitString {
    public static final int objectSigning = 16;
    public static final int objectSigningCA = 1;
    public static final int reserved = 8;
    public static final int smime = 32;
    public static final int smimeCA = 2;
    public static final int sslCA = 4;
    public static final int sslClient = 128;
    public static final int sslServer = 64;

    public NetscapeCertType(int usage) {
        super(getBytes(usage), getPadBits(usage));
    }

    public NetscapeCertType(ASN1BitString usage) {
        super(usage.getBytes(), usage.getPadBits());
    }

    public boolean hasUsages(int usages) {
        return (intValue() & usages) == usages;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitString
    public String toString() {
        return "NetscapeCertType: 0x" + Integer.toHexString(intValue());
    }
}
