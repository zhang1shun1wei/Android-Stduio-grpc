package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class DLSequence extends ASN1Sequence {
    private int contentsLength = -1;

    public DLSequence() {
    }

    public DLSequence(ASN1Encodable element) {
        super(element);
    }

    public DLSequence(ASN1EncodableVector elementVector) {
        super(elementVector);
    }

    public DLSequence(ASN1Encodable[] elements) {
        super(elements);
    }

    DLSequence(ASN1Encodable[] elements, boolean clone) {
        super(elements, clone);
    }

    private int getContentsLength() throws IOException {
        if (this.contentsLength < 0) {
            int count = this.elements.length;
            int totalLength = 0;
            for (int i = 0; i < count; i++) {
                totalLength += this.elements[i].toASN1Primitive().toDLObject().encodedLength(true);
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
        ASN1OutputStream dlOut = out.getDLSubStream();
        int count = this.elements.length;
        if (this.contentsLength >= 0 || count > 16) {
            out.writeDL(getContentsLength());
            for (int i = 0; i < count; i++) {
                dlOut.writePrimitive(this.elements[i].toASN1Primitive(), true);
            }
            return;
        }
        int totalLength = 0;
        ASN1Primitive[] dlObjects = new ASN1Primitive[count];
        for (int i2 = 0; i2 < count; i2++) {
            ASN1Primitive dlObject = this.elements[i2].toASN1Primitive().toDLObject();
            dlObjects[i2] = dlObject;
            totalLength += dlObject.encodedLength(true);
        }
        this.contentsLength = totalLength;
        out.writeDL(totalLength);
        for (int i3 = 0; i3 < count; i3++) {
            dlOut.writePrimitive(dlObjects[i3], true);
        }
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1BitString toASN1BitString() {
        return new DLBitString(BERBitString.flattenBitStrings(getConstructedBitStrings()), false);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1External toASN1External() {
        return new DLExternal(this);
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
    public ASN1Primitive toDLObject() {
        return this;
    }
}
