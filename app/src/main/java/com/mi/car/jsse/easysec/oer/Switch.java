package com.mi.car.jsse.easysec.oer;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;

public interface Switch {
    ASN1Encodable[] keys();

    Element result(SwitchIndexer switchIndexer);
}
