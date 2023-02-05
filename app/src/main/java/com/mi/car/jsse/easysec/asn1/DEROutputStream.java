package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;
import java.io.OutputStream;

/* access modifiers changed from: package-private */
public class DEROutputStream extends DLOutputStream {
    DEROutputStream(OutputStream os) {
        super(os);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1OutputStream
    public DEROutputStream getDERSubStream() {
        return this;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1OutputStream, com.mi.car.jsse.easysec.asn1.DLOutputStream
    public void writeElements(ASN1Encodable[] elements) throws IOException {
        for (ASN1Encodable aSN1Encodable : elements) {
            aSN1Encodable.toASN1Primitive().toDERObject().encode(this, true);
        }
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1OutputStream, com.mi.car.jsse.easysec.asn1.DLOutputStream
    public void writePrimitive(ASN1Primitive primitive, boolean withTag) throws IOException {
        primitive.toDERObject().encode(this, withTag);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1OutputStream, com.mi.car.jsse.easysec.asn1.DLOutputStream
    public void writePrimitives(ASN1Primitive[] primitives) throws IOException {
        for (ASN1Primitive aSN1Primitive : primitives) {
            aSN1Primitive.toDERObject().encode(this, true);
        }
    }
}
