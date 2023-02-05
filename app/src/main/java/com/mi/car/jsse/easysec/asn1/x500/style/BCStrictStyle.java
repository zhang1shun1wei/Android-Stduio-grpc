package com.mi.car.jsse.easysec.asn1.x500.style;

import com.mi.car.jsse.easysec.asn1.x500.RDN;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x500.X500NameStyle;

public class BCStrictStyle extends BCStyle {
    public static final X500NameStyle INSTANCE = new BCStrictStyle();

    @Override // com.mi.car.jsse.easysec.asn1.x500.style.AbstractX500NameStyle, com.mi.car.jsse.easysec.asn1.x500.X500NameStyle
    public boolean areEqual(X500Name name1, X500Name name2) {
        RDN[] rdns1 = name1.getRDNs();
        RDN[] rdns2 = name2.getRDNs();
        if (rdns1.length != rdns2.length) {
            return false;
        }
        for (int i = 0; i != rdns1.length; i++) {
            if (!rdnAreEqual(rdns1[i], rdns2[i])) {
                return false;
            }
        }
        return true;
    }
}
