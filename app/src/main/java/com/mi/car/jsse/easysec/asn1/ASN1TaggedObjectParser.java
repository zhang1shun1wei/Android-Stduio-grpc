package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public interface ASN1TaggedObjectParser extends ASN1Encodable, InMemoryRepresentable {
    ASN1Encodable getObjectParser(int i, boolean z) throws IOException;

    int getTagClass();

    int getTagNo();

    boolean hasContextTag(int i);

    boolean hasTag(int i, int i2);

    ASN1Encodable parseBaseUniversal(boolean z, int i) throws IOException;

    ASN1Encodable parseExplicitBaseObject() throws IOException;

    ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException;

    ASN1TaggedObjectParser parseImplicitBaseTagged(int i, int i2) throws IOException;
}
