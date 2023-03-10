package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class DERTaggedObject extends ASN1TaggedObject {
    public DERTaggedObject(int tagNo, ASN1Encodable encodable) {
        super(true, tagNo, encodable);
    }

    public DERTaggedObject(int tagClass, int tagNo, ASN1Encodable obj) {
        super(true, tagClass, tagNo, obj);
    }

    public DERTaggedObject(boolean explicit, int tagNo, ASN1Encodable obj) {
        super(explicit, tagNo, obj);
    }

    public DERTaggedObject(boolean explicit, int tagClass, int tagNo, ASN1Encodable obj) {
        super(explicit, tagClass, tagNo, obj);
    }

    DERTaggedObject(int explicitness, int tagClass, int tagNo, ASN1Encodable obj) {
        super(explicitness, tagClass, tagNo, obj);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return isExplicit() || this.obj.toASN1Primitive().toDERObject().encodeConstructed();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) throws IOException {
        ASN1Primitive primitive = this.obj.toASN1Primitive().toDERObject();
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
        ASN1Primitive primitive = this.obj.toASN1Primitive().toDERObject();
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
        primitive.encode(out.getDERSubStream(), explicit);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public String getASN1Encoding() {
        return ASN1Encoding.DER;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1Sequence rebuildConstructed(ASN1Primitive primitive) {
        return new DERSequence(primitive);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1TaggedObject replaceTag(int tagClass, int tagNo) {
        return new DERTaggedObject(this.explicitness, tagClass, tagNo, this.obj);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return this;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }
}
