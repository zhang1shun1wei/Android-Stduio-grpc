package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class DLSequenceParser implements ASN1SequenceParser {
    private ASN1StreamParser _parser;

    DLSequenceParser(ASN1StreamParser parser) {
        this._parser = parser;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1SequenceParser
    public ASN1Encodable readObject() throws IOException {
        return this._parser.readObject();
    }

    @Override // com.mi.car.jsse.easysec.asn1.InMemoryRepresentable
    public ASN1Primitive getLoadedObject() throws IOException {
        return DLFactory.createSequence(this._parser.readVector());
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        try {
            return getLoadedObject();
        } catch (IOException e) {
            throw new IllegalStateException(e.getMessage());
        }
    }
}
