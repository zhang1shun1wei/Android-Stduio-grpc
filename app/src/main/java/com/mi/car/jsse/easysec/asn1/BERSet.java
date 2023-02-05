package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class BERSet extends ASN1Set {
    public BERSet() {
    }

    public BERSet(ASN1Encodable element) {
        super(element);
    }

    public BERSet(ASN1EncodableVector elementVector) {
        super(elementVector, false);
    }

    public BERSet(ASN1Encodable[] elements) {
        super(elements, false);
    }

    BERSet(boolean isSorted, ASN1Encodable[] elements) {
        super(isSorted, elements);
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
        out.writeEncodingIL(withTag, 49, this.elements);
    }
}
