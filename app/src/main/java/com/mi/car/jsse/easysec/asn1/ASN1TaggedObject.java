package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public abstract class ASN1TaggedObject extends ASN1Primitive implements ASN1TaggedObjectParser {
    private static final int DECLARED_EXPLICIT = 1;
    private static final int DECLARED_IMPLICIT = 2;
    private static final int PARSED_EXPLICIT = 3;
    private static final int PARSED_IMPLICIT = 4;
    final int explicitness;
    final ASN1Encodable obj;
    final int tagClass;
    final int tagNo;

    /* access modifiers changed from: package-private */
    public abstract String getASN1Encoding();

    /* access modifiers changed from: package-private */
    public abstract ASN1Sequence rebuildConstructed(ASN1Primitive aSN1Primitive);

    /* access modifiers changed from: package-private */
    public abstract ASN1TaggedObject replaceTag(int i, int i2);

    public static ASN1TaggedObject getInstance(Object obj2) {
        if (obj2 == null || (obj2 instanceof ASN1TaggedObject)) {
            return (ASN1TaggedObject) obj2;
        }
        if (obj2 instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj2).toASN1Primitive();
            if (primitive instanceof ASN1TaggedObject) {
                return (ASN1TaggedObject) primitive;
            }
        } else if (obj2 instanceof byte[]) {
            try {
                return checkedCast(fromByteArray((byte[]) obj2));
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct tagged object from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("unknown object in getInstance: " + obj2.getClass().getName());
    }

    public static ASN1TaggedObject getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit) {
        if (128 != taggedObject.getTagClass()) {
            throw new IllegalStateException("this method only valid for CONTEXT_SPECIFIC tags");
        } else if (declaredExplicit) {
            return taggedObject.getExplicitBaseTagged();
        } else {
            throw new IllegalArgumentException("this method not valid for implicitly tagged tagged objects");
        }
    }

    protected ASN1TaggedObject(boolean explicit, int tagNo2, ASN1Encodable obj2) {
        this(explicit, 128, tagNo2, obj2);
    }

    /* JADX INFO: this call moved to the top of the method (can break code semantics) */
    protected ASN1TaggedObject(boolean explicit, int tagClass2, int tagNo2, ASN1Encodable obj2) {
        this(explicit ? 1 : 2, tagClass2, tagNo2, obj2);
    }

    ASN1TaggedObject(int explicitness2, int tagClass2, int tagNo2, ASN1Encodable obj2) {
        if (obj2 == null) {
            throw new NullPointerException("'obj' cannot be null");
        } else if (tagClass2 == 0 || (tagClass2 & BERTags.PRIVATE) != tagClass2) {
            throw new IllegalArgumentException("invalid tag class: " + tagClass2);
        } else {
            this.explicitness = obj2 instanceof ASN1Choice ? 1 : explicitness2;
            this.tagClass = tagClass2;
            this.tagNo = tagNo2;
            this.obj = obj2;
        }
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final boolean asn1Equals(ASN1Primitive other) {
        if (!(other instanceof ASN1TaggedObject)) {
            return false;
        }
        ASN1TaggedObject that = (ASN1TaggedObject) other;
        if (this.tagNo != that.tagNo || this.tagClass != that.tagClass) {
            return false;
        }
        if (this.explicitness != that.explicitness && isExplicit() != that.isExplicit()) {
            return false;
        }
        ASN1Primitive p1 = this.obj.toASN1Primitive();
        ASN1Primitive p2 = that.obj.toASN1Primitive();
        if (p1 == p2) {
            return true;
        }
        if (isExplicit()) {
            return p1.asn1Equals(p2);
        }
        try {
            return Arrays.areEqual(getEncoded(), that.getEncoded());
        } catch (IOException e) {
            return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        return ((isExplicit() ? 15 : 240) ^ (this.tagNo ^ (this.tagClass * 7919))) ^ this.obj.toASN1Primitive().hashCode();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public int getTagClass() {
        return this.tagClass;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public int getTagNo() {
        return this.tagNo;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public boolean hasContextTag(int tagNo2) {
        return this.tagClass == 128 && this.tagNo == tagNo2;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public boolean hasTag(int tagClass2, int tagNo2) {
        return this.tagClass == tagClass2 && this.tagNo == tagNo2;
    }

    public boolean isExplicit() {
        switch (this.explicitness) {
            case 1:
            case 3:
                return true;
            case 2:
            default:
                return false;
        }
    }

    /* access modifiers changed from: package-private */
    public boolean isParsed() {
        switch (this.explicitness) {
            case 3:
            case 4:
                return true;
            default:
                return false;
        }
    }

    /* access modifiers changed from: package-private */
    public byte[] getContents() {
        int contentsLength;
        try {
            byte[] baseEncoding = this.obj.toASN1Primitive().getEncoded(getASN1Encoding());
            if (isExplicit()) {
                return baseEncoding;
            }
            ByteArrayInputStream input = new ByteArrayInputStream(baseEncoding);
            ASN1InputStream.readTagNumber(input, input.read());
            int length = ASN1InputStream.readLength(input, input.available(), false);
            int remaining = input.available();
            if (length < 0) {
                contentsLength = remaining - 2;
            } else {
                contentsLength = remaining;
            }
            if (contentsLength < 0) {
                throw new ASN1ParsingException("failed to get contents");
            }
            byte[] contents = new byte[contentsLength];
            System.arraycopy(baseEncoding, baseEncoding.length - remaining, contents, 0, contentsLength);
            return contents;
        } catch (IOException e) {
            throw new ASN1ParsingException("failed to get contents", e);
        }
    }

    /* access modifiers changed from: package-private */
    public boolean isConstructed() {
        return encodeConstructed();
    }

    public ASN1Primitive getObject() {
        if (128 == getTagClass()) {
            return this.obj.toASN1Primitive();
        }
        throw new IllegalStateException("this method only valid for CONTEXT_SPECIFIC tags");
    }

    public ASN1Object getBaseObject() {
        return this.obj instanceof ASN1Object ? (ASN1Object) this.obj : this.obj.toASN1Primitive();
    }

    public ASN1Object getExplicitBaseObject() {
        if (isExplicit()) {
            return this.obj instanceof ASN1Object ? (ASN1Object) this.obj : this.obj.toASN1Primitive();
        }
        throw new IllegalStateException("object implicit - explicit expected.");
    }

    public ASN1TaggedObject getExplicitBaseTagged() {
        if (isExplicit()) {
            return checkedCast(this.obj.toASN1Primitive());
        }
        throw new IllegalStateException("object implicit - explicit expected.");
    }

    public ASN1TaggedObject getImplicitBaseTagged(int baseTagClass, int baseTagNo) {
        if (baseTagClass == 0 || (baseTagClass & BERTags.PRIVATE) != baseTagClass) {
            throw new IllegalArgumentException("invalid base tag class: " + baseTagClass);
        }
        switch (this.explicitness) {
            case 1:
                throw new IllegalStateException("object explicit - implicit expected.");
            case 2:
                return ASN1Util.checkTag(checkedCast(this.obj.toASN1Primitive()), baseTagClass, baseTagNo);
            default:
                return replaceTag(baseTagClass, baseTagNo);
        }
    }

    public ASN1Primitive getBaseUniversal(boolean declaredExplicit, int tagNo2) {
        ASN1UniversalType universalType = ASN1UniversalTypes.get(tagNo2);
        if (universalType != null) {
            return getBaseUniversal(declaredExplicit, universalType);
        }
        throw new IllegalArgumentException("unsupported UNIVERSAL tag number: " + tagNo2);
    }

    /* access modifiers changed from: package-private */
    public ASN1Primitive getBaseUniversal(boolean declaredExplicit, ASN1UniversalType universalType) {
        if (declaredExplicit) {
            if (isExplicit()) {
                return universalType.checkedCast(this.obj.toASN1Primitive());
            }
            throw new IllegalStateException("object explicit - implicit expected.");
        } else if (1 == this.explicitness) {
            throw new IllegalStateException("object explicit - implicit expected.");
        } else {
            ASN1Primitive primitive = this.obj.toASN1Primitive();
            switch (this.explicitness) {
                case 3:
                    return universalType.fromImplicitConstructed(rebuildConstructed(primitive));
                case 4:
                    if (primitive instanceof ASN1Sequence) {
                        return universalType.fromImplicitConstructed((ASN1Sequence) primitive);
                    }
                    return universalType.fromImplicitPrimitive((DEROctetString) primitive);
                default:
                    return universalType.checkedCast(primitive);
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public ASN1Encodable getObjectParser(int tag, boolean isExplicit) throws IOException {
        if (128 == getTagClass()) {
            return parseBaseUniversal(isExplicit, tag);
        }
        throw new ASN1Exception("this method only valid for CONTEXT_SPECIFIC tags");
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo) throws IOException {
        ASN1Primitive primitive = getBaseUniversal(declaredExplicit, baseTagNo);
        switch (baseTagNo) {
            case 3:
                return ((ASN1BitString) primitive).parser();
            case 4:
                return ((ASN1OctetString) primitive).parser();
            case 16:
                return ((ASN1Sequence) primitive).parser();
            case 17:
                return ((ASN1Set) primitive).parser();
            default:
                return primitive;
        }
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public ASN1Encodable parseExplicitBaseObject() throws IOException {
        return getExplicitBaseObject();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException {
        return getExplicitBaseTagged();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser
    public ASN1TaggedObjectParser parseImplicitBaseTagged(int baseTagClass, int baseTagNo) throws IOException {
        return getImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    @Override // com.mi.car.jsse.easysec.asn1.InMemoryRepresentable
    public final ASN1Primitive getLoadedObject() {
        return this;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return new DERTaggedObject(this.explicitness, this.tagClass, this.tagNo, this.obj);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return new DLTaggedObject(this.explicitness, this.tagClass, this.tagNo, this.obj);
    }

    public String toString() {
        return ASN1Util.getTagText(this.tagClass, this.tagNo) + this.obj;
    }

    static ASN1Primitive createConstructedDL(int tagClass2, int tagNo2, ASN1EncodableVector contentsElements) {
        ASN1TaggedObject taggedObject;
        boolean maybeExplicit = true;
        if (contentsElements.size() != 1) {
            maybeExplicit = false;
        }
        if (maybeExplicit) {
            taggedObject = new DLTaggedObject(3, tagClass2, tagNo2, contentsElements.get(0));
        } else {
            taggedObject = new DLTaggedObject(4, tagClass2, tagNo2, DLFactory.createSequence(contentsElements));
        }
        switch (tagClass2) {
            case 64:
                return new DLApplicationSpecific(taggedObject);
            default:
                return taggedObject;
        }
    }

    static ASN1Primitive createConstructedIL(int tagClass2, int tagNo2, ASN1EncodableVector contentsElements) {
        ASN1TaggedObject taggedObject;
        boolean maybeExplicit = true;
        if (contentsElements.size() != 1) {
            maybeExplicit = false;
        }
        if (maybeExplicit) {
            taggedObject = new BERTaggedObject(3, tagClass2, tagNo2, contentsElements.get(0));
        } else {
            taggedObject = new BERTaggedObject(4, tagClass2, tagNo2, BERFactory.createSequence(contentsElements));
        }
        switch (tagClass2) {
            case 64:
                return new BERApplicationSpecific(taggedObject);
            default:
                return taggedObject;
        }
    }

    static ASN1Primitive createPrimitive(int tagClass2, int tagNo2, byte[] contentsOctets) {
        ASN1TaggedObject taggedObject = new DLTaggedObject(4, tagClass2, tagNo2, new DEROctetString(contentsOctets));
        switch (tagClass2) {
            case 64:
                return new DLApplicationSpecific(taggedObject);
            default:
                return taggedObject;
        }
    }

    private static ASN1TaggedObject checkedCast(ASN1Primitive primitive) {
        if (primitive instanceof ASN1TaggedObject) {
            return (ASN1TaggedObject) primitive;
        }
        throw new IllegalStateException("unexpected object: " + primitive.getClass().getName());
    }
}
