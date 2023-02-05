package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public abstract class ASN1ApplicationSpecific extends ASN1TaggedObject implements ASN1ApplicationSpecificParser {
    final ASN1TaggedObject taggedObject;

    public static ASN1ApplicationSpecific getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1ApplicationSpecific)) {
            return (ASN1ApplicationSpecific) obj;
        }
        if (obj instanceof byte[]) {
            try {
                return getInstance((Object) ASN1Primitive.fromByteArray((byte[]) obj));
            } catch (IOException e) {
                throw new IllegalArgumentException("Failed to construct object from byte[]: " + e.getMessage());
            }
        } else {
            throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
        }
    }

    ASN1ApplicationSpecific(ASN1TaggedObject taggedObject2) {
        super(taggedObject2.explicitness, checkTagClass(taggedObject2.tagClass), taggedObject2.tagNo, taggedObject2.obj);
        this.taggedObject = taggedObject2;
    }

    public int getApplicationTag() {
        return this.taggedObject.getTagNo();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public byte[] getContents() {
        return this.taggedObject.getContents();
    }

    public ASN1Primitive getEnclosedObject() throws IOException {
        return this.taggedObject.getBaseObject().toASN1Primitive();
    }

    public ASN1Primitive getObject(int tagNo) throws IOException {
        return this.taggedObject.getBaseUniversal(false, tagNo);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser, com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1Encodable getObjectParser(int tag, boolean isExplicit) throws IOException {
        throw new ASN1Exception("this method only valid for CONTEXT_SPECIFIC tags");
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser, com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo) throws IOException {
        return this.taggedObject.parseBaseUniversal(declaredExplicit, baseTagNo);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser, com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1Encodable parseExplicitBaseObject() throws IOException {
        return this.taggedObject.parseExplicitBaseObject();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser, com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException {
        return this.taggedObject.parseExplicitBaseTagged();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser, com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1TaggedObjectParser parseImplicitBaseTagged(int baseTagClass, int baseTagNo) throws IOException {
        return this.taggedObject.parseImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    public boolean hasApplicationTag(int tagNo) {
        return this.tagNo == tagNo;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser, com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public boolean hasContextTag(int tagNo) {
        return false;
    }

    public ASN1TaggedObject getTaggedObject() {
        return this.taggedObject;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public boolean isConstructed() {
        return this.taggedObject.isConstructed();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1ApplicationSpecificParser
    public ASN1Encodable readObject() throws IOException {
        return parseExplicitBaseObject();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return this.taggedObject.encodeConstructed();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) throws IOException {
        return this.taggedObject.encodedLength(withTag);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        this.taggedObject.encode(out, withTag);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public String getASN1Encoding() {
        return this.taggedObject.getASN1Encoding();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1Sequence rebuildConstructed(ASN1Primitive primitive) {
        return this.taggedObject.rebuildConstructed(primitive);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1TaggedObject replaceTag(int tagClass, int tagNo) {
        return this.taggedObject.replaceTag(tagClass, tagNo);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return new DERApplicationSpecific((ASN1TaggedObject) this.taggedObject.toDERObject());
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return new DLApplicationSpecific((ASN1TaggedObject) this.taggedObject.toDLObject());
    }

    private static int checkTagClass(int tagClass) {
        if (64 == tagClass) {
            return tagClass;
        }
        throw new IllegalArgumentException();
    }
}
