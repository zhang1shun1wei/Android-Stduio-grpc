package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.IOException;
import java.io.InputStream;

public class BERBitStringParser implements ASN1BitStringParser {
    private ConstructedBitStream _bitStream;
    private ASN1StreamParser _parser;

    BERBitStringParser(ASN1StreamParser parser) {
        this._parser = parser;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitStringParser
    public InputStream getOctetStream() throws IOException {
        ConstructedBitStream constructedBitStream = new ConstructedBitStream(this._parser, true);
        this._bitStream = constructedBitStream;
        return constructedBitStream;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitStringParser
    public InputStream getBitStream() throws IOException {
        ConstructedBitStream constructedBitStream = new ConstructedBitStream(this._parser, false);
        this._bitStream = constructedBitStream;
        return constructedBitStream;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitStringParser
    public int getPadBits() {
        return this._bitStream.getPadBits();
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

    static BERBitString parse(ASN1StreamParser sp) throws IOException {
        ConstructedBitStream bitStream = new ConstructedBitStream(sp, false);
        return new BERBitString(Streams.readAll(bitStream), bitStream.getPadBits());
    }
}
