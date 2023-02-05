package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

/* access modifiers changed from: package-private */
public class DLTaggedObjectParser extends BERTaggedObjectParser {
    private final boolean _constructed;

    DLTaggedObjectParser(int tagClass, int tagNo, boolean constructed, ASN1StreamParser parser) {
        super(tagClass, tagNo, parser);
        this._constructed = constructed;
    }

    @Override // com.mi.car.jsse.easysec.asn1.BERTaggedObjectParser
    public boolean isConstructed() {
        return this._constructed;
    }

    @Override // com.mi.car.jsse.easysec.asn1.InMemoryRepresentable, com.mi.car.jsse.easysec.asn1.BERTaggedObjectParser
    public ASN1Primitive getLoadedObject() throws IOException {
        return this._parser.loadTaggedDL(this._tagClass, this._tagNo, this._constructed);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser, com.mi.car.jsse.easysec.asn1.BERTaggedObjectParser
    public ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo) throws IOException {
        if (declaredExplicit) {
            if (this._constructed) {
                return this._parser.parseObject(baseTagNo);
            }
            throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
        } else if (this._constructed) {
            return this._parser.parseImplicitConstructedDL(baseTagNo);
        } else {
            return this._parser.parseImplicitPrimitive(baseTagNo);
        }
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser, com.mi.car.jsse.easysec.asn1.BERTaggedObjectParser
    public ASN1Encodable parseExplicitBaseObject() throws IOException {
        if (this._constructed) {
            return this._parser.readObject();
        }
        throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser, com.mi.car.jsse.easysec.asn1.BERTaggedObjectParser
    public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException {
        if (this._constructed) {
            return this._parser.parseTaggedObject();
        }
        throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser, com.mi.car.jsse.easysec.asn1.BERTaggedObjectParser
    public ASN1TaggedObjectParser parseImplicitBaseTagged(int baseTagClass, int baseTagNo) throws IOException {
        if (64 == baseTagClass) {
            return (DLApplicationSpecific) this._parser.loadTaggedDL(baseTagClass, baseTagNo, this._constructed);
        }
        return new DLTaggedObjectParser(baseTagClass, baseTagNo, this._constructed, this._parser);
    }
}
