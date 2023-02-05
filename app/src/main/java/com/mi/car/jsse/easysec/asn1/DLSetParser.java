package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class DLSetParser implements ASN1SetParser {
    private ASN1StreamParser _parser;

    DLSetParser(ASN1StreamParser parser) {
        this._parser = parser;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1SetParser
    public ASN1Encodable readObject() throws IOException {
        return this._parser.readObject();
    }

    @Override // com.mi.car.jsse.easysec.asn1.InMemoryRepresentable
    public ASN1Primitive getLoadedObject() throws IOException {
        return DLFactory.createSet(this._parser.readVector());
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        try {
            return getLoadedObject();
        } catch (IOException e) {
            throw new ASN1ParsingException(e.getMessage(), e);
        }
    }
}
