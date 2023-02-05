//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1SequenceParser;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import java.io.IOException;

public class CompressedDataParser {
    private ASN1Integer _version;
    private AlgorithmIdentifier _compressionAlgorithm;
    private ContentInfoParser _encapContentInfo;

    public CompressedDataParser(ASN1SequenceParser seq) throws IOException {
        this._version = (ASN1Integer)seq.readObject();
        this._compressionAlgorithm = AlgorithmIdentifier.getInstance(seq.readObject().toASN1Primitive());
        this._encapContentInfo = new ContentInfoParser((ASN1SequenceParser)seq.readObject());
    }

    public ASN1Integer getVersion() {
        return this._version;
    }

    public AlgorithmIdentifier getCompressionAlgorithmIdentifier() {
        return this._compressionAlgorithm;
    }

    public ContentInfoParser getEncapContentInfo() {
        return this._encapContentInfo;
    }
}
