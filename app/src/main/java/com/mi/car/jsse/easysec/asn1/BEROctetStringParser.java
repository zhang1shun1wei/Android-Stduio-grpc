package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.IOException;
import java.io.InputStream;

public class BEROctetStringParser implements ASN1OctetStringParser {
    private ASN1StreamParser _parser;

    BEROctetStringParser(ASN1StreamParser parser) {
        this._parser = parser;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1OctetStringParser
    public InputStream getOctetStream() {
        return new ConstructedOctetStream(this._parser);
    }

    @Override // com.mi.car.jsse.easysec.asn1.InMemoryRepresentable
    public ASN1Primitive getLoadedObject() throws IOException {
        return parse(this._parser);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        try {
            return getLoadedObject();
        } catch (IOException e) {
            throw new ASN1ParsingException("IOException converting stream to byte array: " + e.getMessage(), e);
        }
    }

    static BEROctetString parse(ASN1StreamParser sp) throws IOException {
        return new BEROctetString(Streams.readAll(new ConstructedOctetStream(sp)));
    }
}
