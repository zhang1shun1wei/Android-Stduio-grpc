package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

/* access modifiers changed from: package-private */
public abstract class ASN1UniversalType extends ASN1Type {
    final ASN1Tag tag;

    ASN1UniversalType(Class javaClass, int tagNumber) {
        super(javaClass);
        this.tag = ASN1Tag.create(0, tagNumber);
    }

    /* access modifiers changed from: package-private */
    public final ASN1Primitive checkedCast(ASN1Primitive primitive) {
        if (this.javaClass.isInstance(primitive)) {
            return primitive;
        }
        throw new IllegalStateException("unexpected object: " + primitive.getClass().getName());
    }

    /* access modifiers changed from: package-private */
    public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
        throw new IllegalStateException("unexpected implicit primitive encoding");
    }

    /* access modifiers changed from: package-private */
    public ASN1Primitive fromImplicitConstructed(ASN1Sequence sequence) {
        throw new IllegalStateException("unexpected implicit constructed encoding");
    }

    /* access modifiers changed from: package-private */
    public final ASN1Primitive fromByteArray(byte[] bytes) throws IOException {
        return checkedCast(ASN1Primitive.fromByteArray(bytes));
    }

    /* access modifiers changed from: package-private */
    public final ASN1Primitive getContextInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit) {
        if (128 == taggedObject.getTagClass()) {
            return checkedCast(taggedObject.getBaseUniversal(declaredExplicit, this));
        }
        throw new IllegalStateException("this method only valid for CONTEXT_SPECIFIC tags");
    }

    /* access modifiers changed from: package-private */
    public final ASN1Tag getTag() {
        return this.tag;
    }
}
