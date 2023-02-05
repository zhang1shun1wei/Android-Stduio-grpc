package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;
import java.io.OutputStream;

/* access modifiers changed from: package-private */
public class DLOutputStream extends ASN1OutputStream {
    DLOutputStream(OutputStream os) {
        super(os);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1OutputStream
    public DLOutputStream getDLSubStream() {
        return this;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1OutputStream
    public void writeElements(ASN1Encodable[] elements) throws IOException {
        for (ASN1Encodable aSN1Encodable : elements) {
            aSN1Encodable.toASN1Primitive().toDLObject().encode(this, true);
        }
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1OutputStream
    public void writePrimitive(ASN1Primitive primitive, boolean withTag) throws IOException {
        primitive.toDLObject().encode(this, withTag);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1OutputStream
    public void writePrimitives(ASN1Primitive[] primitives) throws IOException {
        for (ASN1Primitive aSN1Primitive : primitives) {
            aSN1Primitive.toDLObject().encode(this, true);
        }
    }
}
