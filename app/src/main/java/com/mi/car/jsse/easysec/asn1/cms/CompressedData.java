//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.BERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class CompressedData extends ASN1Object {
    private ASN1Integer version;
    private AlgorithmIdentifier compressionAlgorithm;
    private ContentInfo encapContentInfo;

    public CompressedData(AlgorithmIdentifier compressionAlgorithm, ContentInfo encapContentInfo) {
        this.version = new ASN1Integer(0L);
        this.compressionAlgorithm = compressionAlgorithm;
        this.encapContentInfo = encapContentInfo;
    }

    private CompressedData(ASN1Sequence seq) {
        this.version = (ASN1Integer)seq.getObjectAt(0);
        this.compressionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.encapContentInfo = ContentInfo.getInstance(seq.getObjectAt(2));
    }

    public static CompressedData getInstance(ASN1TaggedObject ato, boolean isExplicit) {
        return getInstance(ASN1Sequence.getInstance(ato, isExplicit));
    }

    public static CompressedData getInstance(Object obj) {
        if (obj instanceof CompressedData) {
            return (CompressedData)obj;
        } else {
            return obj != null ? new CompressedData(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public AlgorithmIdentifier getCompressionAlgorithmIdentifier() {
        return this.compressionAlgorithm;
    }

    public ContentInfo getEncapContentInfo() {
        return this.encapContentInfo;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.version);
        v.add(this.compressionAlgorithm);
        v.add(this.encapContentInfo);
        return new BERSequence(v);
    }
}
