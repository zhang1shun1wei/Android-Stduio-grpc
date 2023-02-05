package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class BERApplicationSpecificParser extends BERTaggedObjectParser implements ASN1ApplicationSpecificParser {
    BERApplicationSpecificParser(int tagNo, ASN1StreamParser parser) {
        super(64, tagNo, parser);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1ApplicationSpecificParser
    public ASN1Encodable readObject() throws IOException {
        return parseExplicitBaseObject();
    }
}
