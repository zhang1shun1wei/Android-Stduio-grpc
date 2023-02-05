package com.mi.car.jsse.easysec.asn1;

public class DLExternal extends ASN1External {
    public DLExternal(ASN1EncodableVector vector) {
        this(DLFactory.createSequence(vector));
    }

    public DLExternal(DLSequence sequence) {
        super(sequence);
    }

    public DLExternal(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor, DERTaggedObject externalData) {
        super(directReference, indirectReference, dataValueDescriptor, externalData);
    }

    public DLExternal(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor, int encoding, ASN1Primitive externalData) {
        super(directReference, indirectReference, dataValueDescriptor, encoding, externalData);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1External
    public ASN1Sequence buildSequence() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        if (this.directReference != null) {
            v.add(this.directReference);
        }
        if (this.indirectReference != null) {
            v.add(this.indirectReference);
        }
        if (this.dataValueDescriptor != null) {
            v.add(this.dataValueDescriptor.toDLObject());
        }
        v.add(new DLTaggedObject(this.encoding == 0, this.encoding, this.externalContent));
        return new DLSequence(v);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1External, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }
}
