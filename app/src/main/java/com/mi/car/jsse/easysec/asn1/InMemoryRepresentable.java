package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public interface InMemoryRepresentable {
    ASN1Primitive getLoadedObject() throws IOException;
}
