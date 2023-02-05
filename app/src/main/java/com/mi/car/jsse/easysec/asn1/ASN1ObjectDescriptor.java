package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public final class ASN1ObjectDescriptor extends ASN1Primitive {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1ObjectDescriptor.class, 7) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1ObjectDescriptor.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return new ASN1ObjectDescriptor((ASN1GraphicString) ASN1GraphicString.TYPE.fromImplicitPrimitive(octetString));
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitConstructed(ASN1Sequence sequence) {
            return new ASN1ObjectDescriptor((ASN1GraphicString) ASN1GraphicString.TYPE.fromImplicitConstructed(sequence));
        }
    };
    private final ASN1GraphicString baseGraphicString;

    public static ASN1ObjectDescriptor getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1ObjectDescriptor)) {
            return (ASN1ObjectDescriptor) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1ObjectDescriptor) {
                return (ASN1ObjectDescriptor) primitive;
            }
        } else if (obj instanceof byte[]) {
            try {
                return (ASN1ObjectDescriptor) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct object descriptor from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1ObjectDescriptor getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1ObjectDescriptor) TYPE.getContextInstance(taggedObject, explicit);
    }

    public ASN1ObjectDescriptor(ASN1GraphicString baseGraphicString2) {
        if (baseGraphicString2 == null) {
            throw new NullPointerException("'baseGraphicString' cannot be null");
        }
        this.baseGraphicString = baseGraphicString2;
    }

    public ASN1GraphicString getBaseGraphicString() {
        return this.baseGraphicString;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return false;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) {
        return this.baseGraphicString.encodedLength(withTag);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeIdentifier(withTag, 7);
        this.baseGraphicString.encode(out, false);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        ASN1GraphicString der = (ASN1GraphicString) this.baseGraphicString.toDERObject();
        return der == this.baseGraphicString ? this : new ASN1ObjectDescriptor(der);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        ASN1GraphicString dl = (ASN1GraphicString) this.baseGraphicString.toDLObject();
        return dl == this.baseGraphicString ? this : new ASN1ObjectDescriptor(dl);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive other) {
        if (!(other instanceof ASN1ObjectDescriptor)) {
            return false;
        }
        return this.baseGraphicString.asn1Equals(((ASN1ObjectDescriptor) other).baseGraphicString);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        return this.baseGraphicString.hashCode() ^ -1;
    }

    static ASN1ObjectDescriptor createPrimitive(byte[] contents) {
        return new ASN1ObjectDescriptor(ASN1GraphicString.createPrimitive(contents));
    }
}
