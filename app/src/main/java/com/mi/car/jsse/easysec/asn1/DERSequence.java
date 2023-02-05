package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class DERSequence extends ASN1Sequence {
    private int contentsLength = -1;

    public static DERSequence convert(ASN1Sequence seq) {
        return (DERSequence) seq.toDERObject();
    }

    public DERSequence() {
    }

    public DERSequence(ASN1Encodable element) {
        super(element);
    }

    public DERSequence(ASN1EncodableVector elementVector) {
        super(elementVector);
    }

    public DERSequence(ASN1Encodable[] elements) {
        super(elements);
    }

    DERSequence(ASN1Encodable[] elements, boolean clone) {
        super(elements, clone);
    }

    private int getContentsLength() throws IOException {
        if (this.contentsLength < 0) {
            int count = this.elements.length;
            int totalLength = 0;
            for (int i = 0; i < count; i++) {
                totalLength += this.elements[i].toASN1Primitive().toDERObject().encodedLength(true);
            }
            this.contentsLength = totalLength;
        }
        return this.contentsLength;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) throws IOException {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, getContentsLength());
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeIdentifier(withTag, 48);
        DEROutputStream derOut = out.getDERSubStream();
        int count = this.elements.length;
        if (this.contentsLength >= 0 || count > 16) {
            out.writeDL(getContentsLength());
            for (int i = 0; i < count; i++) {
                this.elements[i].toASN1Primitive().toDERObject().encode(derOut, true);
            }
            return;
        }
        int totalLength = 0;
        ASN1Primitive[] derObjects = new ASN1Primitive[count];
        for (int i2 = 0; i2 < count; i2++) {
            ASN1Primitive derObject = this.elements[i2].toASN1Primitive().toDERObject();
            derObjects[i2] = derObject;
            totalLength += derObject.encodedLength(true);
        }
        this.contentsLength = totalLength;
        out.writeDL(totalLength);
        for (int i3 = 0; i3 < count; i3++) {
            derObjects[i3].encode(derOut, true);
        }
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1BitString toASN1BitString() {
        return new DERBitString(BERBitString.flattenBitStrings(getConstructedBitStrings()), false);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1External toASN1External() {
        return new DERExternal(this);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1OctetString toASN1OctetString() {
        return new DEROctetString(BEROctetString.flattenOctetStrings(getConstructedOctetStrings()));
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1Set toASN1Set() {
        return new DLSet(false, toArrayInternal());
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return this;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }
}
