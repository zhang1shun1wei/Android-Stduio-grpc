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
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import java.io.IOException;

public class EncryptedContentInfoParser {
    private ASN1ObjectIdentifier _contentType;
    private AlgorithmIdentifier _contentEncryptionAlgorithm;
    private ASN1TaggedObjectParser _encryptedContent;

    public EncryptedContentInfoParser(ASN1SequenceParser seq) throws IOException {
        this._contentType = (ASN1ObjectIdentifier)seq.readObject();
        this._contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.readObject().toASN1Primitive());
        this._encryptedContent = (ASN1TaggedObjectParser)seq.readObject();
    }

    public ASN1ObjectIdentifier getContentType() {
        return this._contentType;
    }

    public AlgorithmIdentifier getContentEncryptionAlgorithm() {
        return this._contentEncryptionAlgorithm;
    }

    public ASN1Encodable getEncryptedContent(int tag) throws IOException {
        return ASN1Util.parseContextBaseUniversal(this._encryptedContent, 0, false, tag);
    }
}
