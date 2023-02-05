package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class BERTaggedObjectParser implements ASN1TaggedObjectParser {
    final ASN1StreamParser _parser;
    final int _tagClass;
    final int _tagNo;

    BERTaggedObjectParser(int tagClass, int tagNo, ASN1StreamParser parser) {
        this._tagClass = tagClass;
        this._tagNo = tagNo;
        this._parser = parser;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public int getTagClass() {
        return this._tagClass;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public int getTagNo() {
        return this._tagNo;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public boolean hasContextTag(int tagNo) {
        return this._tagClass == 128 && this._tagNo == tagNo;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public boolean hasTag(int tagClass, int tagNo) {
        return this._tagClass == tagClass && this._tagNo == tagNo;
    }

    public boolean isConstructed() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public ASN1Encodable getObjectParser(int tag, boolean isExplicit) throws IOException {
        if (128 == getTagClass()) {
            return parseBaseUniversal(isExplicit, tag);
        }
        throw new ASN1Exception("this method only valid for CONTEXT_SPECIFIC tags");
    }

    @Override // com.mi.car.jsse.easysec.asn1.InMemoryRepresentable
    public ASN1Primitive getLoadedObject() throws IOException {
        return this._parser.loadTaggedIL(this._tagClass, this._tagNo);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo) throws IOException {
        if (declaredExplicit) {
            return this._parser.parseObject(baseTagNo);
        }
        return this._parser.parseImplicitConstructedIL(baseTagNo);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public ASN1Encodable parseExplicitBaseObject() throws IOException {
        return this._parser.readObject();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException {
        return this._parser.parseTaggedObject();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public ASN1TaggedObjectParser parseImplicitBaseTagged(int baseTagClass, int baseTagNo) throws IOException {
        if (64 == baseTagClass) {
            return new BERApplicationSpecificParser(baseTagNo, this._parser);
        }
        return new BERTaggedObjectParser(baseTagClass, baseTagNo, this._parser);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        try {
            return getLoadedObject();
        } catch (IOException e) {
            throw new ASN1ParsingException(e.getMessage());
        }
    }
}
