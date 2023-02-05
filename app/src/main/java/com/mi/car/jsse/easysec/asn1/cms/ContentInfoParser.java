//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1SequenceParser;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser;
import com.mi.car.jsse.easysec.asn1.ASN1Util;
import java.io.IOException;

public class ContentInfoParser {
    private ASN1ObjectIdentifier contentType;
    private ASN1TaggedObjectParser content;

    public ContentInfoParser(ASN1SequenceParser seq) throws IOException {
        this.contentType = (ASN1ObjectIdentifier)seq.readObject();
        this.content = (ASN1TaggedObjectParser)seq.readObject();
    }

    public ASN1ObjectIdentifier getContentType() {
        return this.contentType;
    }

    public ASN1Encodable getContent(int tag) throws IOException {
        return this.content != null ? ASN1Util.parseExplicitContextBaseObject(this.content, 0) : null;
    }
}
