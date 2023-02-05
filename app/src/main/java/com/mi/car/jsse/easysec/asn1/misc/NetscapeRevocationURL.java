package com.mi.car.jsse.easysec.asn1.misc;

import com.mi.car.jsse.easysec.asn1.ASN1IA5String;
import com.mi.car.jsse.easysec.asn1.DERIA5String;

public class NetscapeRevocationURL extends DERIA5String {
    public NetscapeRevocationURL(ASN1IA5String str) {
        super(str.getString());
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1IA5String
    public String toString() {
        return "NetscapeRevocationURL: " + getString();
    }
}
