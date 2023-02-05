package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class DLSet extends ASN1Set {
    private int contentsLength = -1;

    public DLSet() {
    }

    public DLSet(ASN1Encodable element) {
        super(element);
    }

    public DLSet(ASN1EncodableVector elementVector) {
        super(elementVector, false);
    }

    public DLSet(ASN1Encodable[] elements) {
        super(elements, false);
    }

    DLSet(boolean isSorted, ASN1Encodable[] elements) {
        super(isSorted, elements);
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
        out.writeIdentifier(withTag, 49);
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
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Set, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }
}
