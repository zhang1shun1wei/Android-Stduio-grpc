package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class DLTaggedObject extends ASN1TaggedObject {
    public DLTaggedObject(int tagNo, ASN1Encodable encodable) {
        super(true, tagNo, encodable);
    }

    public DLTaggedObject(int tagClass, int tagNo, ASN1Encodable encodable) {
        super(true, tagClass, tagNo, encodable);
    }

    public DLTaggedObject(boolean explicit, int tagNo, ASN1Encodable obj) {
        super(explicit, tagNo, obj);
    }

    public DLTaggedObject(boolean explicit, int tagClass, int tagNo, ASN1Encodable obj) {
        super(explicit, tagClass, tagNo, obj);
    }

    DLTaggedObject(int explicitness, int tagClass, int tagNo, ASN1Encodable obj) {
        super(explicitness, tagClass, tagNo, obj);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return isExplicit() || this.obj.toASN1Primitive().toDLObject().encodeConstructed();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) throws IOException {
        ASN1Primitive primitive = this.obj.toASN1Primitive().toDLObject();
        boolean explicit = isExplicit();
        int length = primitive.encodedLength(explicit);
        if (explicit) {
            length += ASN1OutputStream.getLengthOfDL(length);
        }
        return length + (withTag ? ASN1OutputStream.getLengthOfIdentifier(this.tagNo) : 0);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        ASN1Primitive primitive = this.obj.toASN1Primitive().toDLObject();
        boolean explicit = isExplicit();
        if (withTag) {
            int flags = this.tagClass;
            if (explicit || primitive.encodeConstructed()) {
                flags |= 32;
            }
            out.writeIdentifier(true, flags, this.tagNo);
        }
        if (explicit) {
            out.writeDL(primitive.encodedLength(true));
        }
        primitive.encode(out.getDLSubStream(), explicit);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public String getASN1Encoding() {
        return ASN1Encoding.DL;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1Sequence rebuildConstructed(ASN1Primitive primitive) {
        return new DLSequence(primitive);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1TaggedObject replaceTag(int tagClass, int tagNo) {
        return new DLTaggedObject(this.explicitness, tagClass, tagNo, this.obj);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }
}
