package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class BERTaggedObject extends ASN1TaggedObject {
    public BERTaggedObject(int tagNo) {
        super(false, tagNo, new BERSequence());
    }

    public BERTaggedObject(int tagNo, ASN1Encodable obj) {
        super(true, tagNo, obj);
    }

    public BERTaggedObject(int tagClass, int tagNo, ASN1Encodable obj) {
        super(true, tagClass, tagNo, obj);
    }

    public BERTaggedObject(boolean explicit, int tagNo, ASN1Encodable obj) {
        super(explicit, tagNo, obj);
    }

    public BERTaggedObject(boolean explicit, int tagClass, int tagNo, ASN1Encodable obj) {
        super(explicit, tagClass, tagNo, obj);
    }

    BERTaggedObject(int explicitness, int tagClass, int tagNo, ASN1Encodable obj) {
        super(explicitness, tagClass, tagNo, obj);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return isExplicit() || this.obj.toASN1Primitive().encodeConstructed();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) throws IOException {
        ASN1Primitive primitive = this.obj.toASN1Primitive();
        boolean explicit = isExplicit();
        int length = primitive.encodedLength(explicit);
        if (explicit) {
            length += 3;
        }
        return length + (withTag ? ASN1OutputStream.getLengthOfIdentifier(this.tagNo) : 0);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        ASN1Primitive primitive = this.obj.toASN1Primitive();
        boolean explicit = isExplicit();
        if (withTag) {
            int flags = this.tagClass;
            if (explicit || primitive.encodeConstructed()) {
                flags |= 32;
            }
            out.writeIdentifier(true, flags, this.tagNo);
        }
        if (explicit) {
            out.write(128);
            primitive.encode(out, true);
            out.write(0);
            out.write(0);
            return;
        }
        primitive.encode(out, false);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public String getASN1Encoding() {
        return ASN1Encoding.BER;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1Sequence rebuildConstructed(ASN1Primitive primitive) {
        return new BERSequence(primitive);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1TaggedObject
    public ASN1TaggedObject replaceTag(int tagClass, int tagNo) {
        return new BERTaggedObject(this.explicitness, tagClass, tagNo, this.obj);
    }
}
