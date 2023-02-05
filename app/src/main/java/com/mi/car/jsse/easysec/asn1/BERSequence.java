package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class BERSequence extends ASN1Sequence {
    public BERSequence() {
    }

    public BERSequence(ASN1Encodable element) {
        super(element);
    }

    public BERSequence(ASN1EncodableVector elementVector) {
        super(elementVector);
    }

    public BERSequence(ASN1Encodable[] elements) {
        super(elements);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) throws IOException {
        int totalLength = withTag ? 4 : 3;
        int count = this.elements.length;
        for (int i = 0; i < count; i++) {
            totalLength += this.elements[i].toASN1Primitive().encodedLength(true);
        }
        return totalLength;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingIL(withTag, 48, this.elements);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1BitString toASN1BitString() {
        return new BERBitString(getConstructedBitStrings());
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1External toASN1External() {
        return ((ASN1Sequence) toDLObject()).toASN1External();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1OctetString toASN1OctetString() {
        return new BEROctetString(getConstructedOctetStrings());
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Sequence
    public ASN1Set toASN1Set() {
        return new BERSet(false, toArrayInternal());
    }
}
