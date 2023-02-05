package com.mi.car.jsse.easysec.asn1;

import java.io.InputStream;

public interface ASN1OctetStringParser extends ASN1Encodable, InMemoryRepresentable {
    InputStream getOctetStream();
}
