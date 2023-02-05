package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class DERExternalParser implements ASN1ExternalParser {
    private ASN1StreamParser _parser;

    public DERExternalParser(ASN1StreamParser parser) {
        this._parser = parser;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1ExternalParser
    public ASN1Encodable readObject() throws IOException {
        return this._parser.readObject();
    }

    @Override // com.mi.car.jsse.easysec.asn1.InMemoryRepresentable
    public ASN1Primitive getLoadedObject() throws IOException {
        return parse(this._parser);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        try {
            return getLoadedObject();
        } catch (IOException ioe) {
            throw new ASN1ParsingException("unable to get DER object", ioe);
        } catch (IllegalArgumentException ioe2) {
            throw new ASN1ParsingException("unable to get DER object", ioe2);
        }
    }

    static DLExternal parse(ASN1StreamParser sp) throws IOException {
        try {
            return new DLExternal(sp.readVector());
        } catch (IllegalArgumentException e) {
            throw new ASN1Exception(e.getMessage(), e);
        }
    }
}
