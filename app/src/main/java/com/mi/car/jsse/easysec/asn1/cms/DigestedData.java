//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.BERSequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.util.Arrays;

public class DigestedData extends ASN1Object {
    private ASN1Integer version;
    private AlgorithmIdentifier digestAlgorithm;
    private ContentInfo encapContentInfo;
    private ASN1OctetString digest;

    public DigestedData(AlgorithmIdentifier digestAlgorithm, ContentInfo encapContentInfo, byte[] digest) {
        this.version = new ASN1Integer(0L);
        this.digestAlgorithm = digestAlgorithm;
        this.encapContentInfo = encapContentInfo;
        this.digest = new DEROctetString(Arrays.clone(digest));
    }

    private DigestedData(ASN1Sequence seq) {
        this.version = (ASN1Integer)seq.getObjectAt(0);
        this.digestAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.encapContentInfo = ContentInfo.getInstance(seq.getObjectAt(2));
        this.digest = ASN1OctetString.getInstance(seq.getObjectAt(3));
    }

    public static DigestedData getInstance(ASN1TaggedObject ato, boolean isExplicit) {
        return getInstance(ASN1Sequence.getInstance(ato, isExplicit));
    }

    public static DigestedData getInstance(Object obj) {
        if (obj instanceof DigestedData) {
            return (DigestedData)obj;
        } else {
            return obj != null ? new DigestedData(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public AlgorithmIdentifier getDigestAlgorithm() {
        return this.digestAlgorithm;
    }

    public ContentInfo getEncapContentInfo() {
        return this.encapContentInfo;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.version);
        v.add(this.digestAlgorithm);
        v.add(this.encapContentInfo);
        v.add(this.digest);
        return new BERSequence(v);
    }

    public byte[] getDigest() {
        return Arrays.clone(this.digest.getOctets());
    }
}
