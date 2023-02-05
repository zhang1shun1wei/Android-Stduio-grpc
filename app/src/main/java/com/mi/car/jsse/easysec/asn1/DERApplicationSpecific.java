package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class DERApplicationSpecific extends ASN1ApplicationSpecific {
    public DERApplicationSpecific(int tagNo, byte[] contentsOctets) {
        super(new DERTaggedObject(false, 64, tagNo, (ASN1Encodable) new DEROctetString(contentsOctets)));
    }

    public DERApplicationSpecific(int tag, ASN1Encodable baseEncodable) throws IOException {
        this(true, tag, baseEncodable);
    }

    public DERApplicationSpecific(boolean explicit, int tagNo, ASN1Encodable baseEncodable) throws IOException {
        super(new DERTaggedObject(explicit, 64, tagNo, baseEncodable));
    }

    public DERApplicationSpecific(int tagNo, ASN1EncodableVector contentsElements) {
        super(new DERTaggedObject(false, 64, tagNo, (ASN1Encodable) DERFactory.createSequence(contentsElements)));
    }

    DERApplicationSpecific(ASN1TaggedObject taggedObject) {
        super(taggedObject);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1ApplicationSpecific, com.mi.car.jsse.easysec.asn1.ASN1TaggedObject, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return this;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1ApplicationSpecific, com.mi.car.jsse.easysec.asn1.ASN1TaggedObject, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }
}
