package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public class DLApplicationSpecific extends ASN1ApplicationSpecific {
    public DLApplicationSpecific(int tagNo, byte[] contentsOctets) {
        super(new DLTaggedObject(false, 64, tagNo, (ASN1Encodable) new DEROctetString(Arrays.clone(contentsOctets))));
    }

    public DLApplicationSpecific(int tagNo, ASN1Encodable baseEncodable) throws IOException {
        this(true, tagNo, baseEncodable);
    }

    public DLApplicationSpecific(boolean explicit, int tagNo, ASN1Encodable baseEncodable) throws IOException {
        super(new DLTaggedObject(explicit, 64, tagNo, baseEncodable));
    }

    public DLApplicationSpecific(int tagNo, ASN1EncodableVector contentsElements) {
        super(new DLTaggedObject(false, 64, tagNo, (ASN1Encodable) DLFactory.createSequence(contentsElements)));
    }

    DLApplicationSpecific(ASN1TaggedObject taggedObject) {
        super(taggedObject);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1ApplicationSpecific, com.mi.car.jsse.easysec.asn1.ASN1TaggedObject, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }
}
