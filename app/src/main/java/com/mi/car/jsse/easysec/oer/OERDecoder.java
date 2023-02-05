package com.mi.car.jsse.easysec.oer;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class OERDecoder {
    public static ASN1Encodable decode(byte[] src, Element e) throws IOException {
        return decode(new ByteArrayInputStream(src), e);
    }

    public static ASN1Encodable decode(InputStream src, Element e) throws IOException {
        return new OERInputStream(src).parse(e);
    }
}
