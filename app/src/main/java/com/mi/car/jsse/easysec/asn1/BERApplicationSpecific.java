package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class BERApplicationSpecific extends ASN1ApplicationSpecific {
    public BERApplicationSpecific(int tagNo, ASN1Encodable baseEncodable) throws IOException {
        this(true, tagNo, baseEncodable);
    }

    public BERApplicationSpecific(boolean explicit, int tagNo, ASN1Encodable baseEncodable) throws IOException {
        super(new BERTaggedObject(explicit, 64, tagNo, baseEncodable));
    }

    public BERApplicationSpecific(int tagNo, ASN1EncodableVector contentsElements) {
        super(new BERTaggedObject(false, 64, tagNo, (ASN1Encodable) BERFactory.createSequence(contentsElements)));
    }

    BERApplicationSpecific(ASN1TaggedObject taggedObject) {
        super(taggedObject);
    }
}
