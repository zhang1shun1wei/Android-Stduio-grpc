package com.mi.car.jsse.easysec.asn1.tsp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.cms.Attributes;
import com.mi.car.jsse.easysec.asn1.cms.CMSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.cms.ContentInfo;
import com.mi.car.jsse.easysec.asn1.cms.SignedData;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class ArchiveTimeStamp extends ASN1Object {
    private final Attributes attributes;
    private final AlgorithmIdentifier digestAlgorithm;
    private final ASN1Sequence reducedHashTree;
    private final ContentInfo timeStamp;

    public static ArchiveTimeStamp getInstance(Object obj) {
        if (obj instanceof ArchiveTimeStamp) {
            return (ArchiveTimeStamp) obj;
        }
        if (obj != null) {
            return new ArchiveTimeStamp(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ArchiveTimeStamp(AlgorithmIdentifier digestAlgorithm2, PartialHashtree[] reducedHashTree2, ContentInfo timeStamp2) {
        this(digestAlgorithm2, null, reducedHashTree2, timeStamp2);
    }

    public ArchiveTimeStamp(ContentInfo timeStamp2) {
        this(null, null, null, timeStamp2);
    }

    public ArchiveTimeStamp(AlgorithmIdentifier digestAlgorithm2, Attributes attributes2, PartialHashtree[] reducedHashTree2, ContentInfo timeStamp2) {
        this.digestAlgorithm = digestAlgorithm2;
        this.attributes = attributes2;
        if (reducedHashTree2 != null) {
            this.reducedHashTree = new DERSequence(reducedHashTree2);
        } else {
            this.reducedHashTree = null;
        }
        this.timeStamp = timeStamp2;
    }

    private ArchiveTimeStamp(ASN1Sequence sequence) {
        if (sequence.size() < 1 || sequence.size() > 4) {
            throw new IllegalArgumentException("wrong sequence size in constructor: " + sequence.size());
        }
        AlgorithmIdentifier digAlg = null;
        Attributes attrs = null;
        ASN1Sequence rHashTree = null;
        for (int i = 0; i < sequence.size() - 1; i++) {
            ASN1Encodable obj = sequence.getObjectAt(i);
            if (obj instanceof ASN1TaggedObject) {
                ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(obj);
                switch (taggedObject.getTagNo()) {
                    case 0:
                        digAlg = AlgorithmIdentifier.getInstance(taggedObject, false);
                        continue;
                    case 1:
                        attrs = Attributes.getInstance(taggedObject, false);
                        continue;
                    case 2:
                        rHashTree = ASN1Sequence.getInstance(taggedObject, false);
                        continue;
                    default:
                        throw new IllegalArgumentException("invalid tag no in constructor: " + taggedObject.getTagNo());
                }
            }
        }
        this.digestAlgorithm = digAlg;
        this.attributes = attrs;
        this.reducedHashTree = rHashTree;
        this.timeStamp = ContentInfo.getInstance(sequence.getObjectAt(sequence.size() - 1));
    }

    public AlgorithmIdentifier getDigestAlgorithmIdentifier() {
        if (this.digestAlgorithm != null) {
            return this.digestAlgorithm;
        }
        if (this.timeStamp.getContentType().equals(CMSObjectIdentifiers.signedData)) {
            SignedData tsData = SignedData.getInstance(this.timeStamp.getContent());
            if (tsData.getEncapContentInfo().getContentType().equals(PKCSObjectIdentifiers.id_ct_TSTInfo)) {
                return TSTInfo.getInstance(tsData.getEncapContentInfo()).getMessageImprint().getHashAlgorithm();
            }
            throw new IllegalStateException("cannot parse time stamp");
        }
        throw new IllegalStateException("cannot identify algorithm identifier for digest");
    }

    public AlgorithmIdentifier getDigestAlgorithm() {
        return this.digestAlgorithm;
    }

    public PartialHashtree[] getReducedHashTree() {
        if (this.reducedHashTree == null) {
            return null;
        }
        PartialHashtree[] rv = new PartialHashtree[this.reducedHashTree.size()];
        for (int i = 0; i != rv.length; i++) {
            rv[i] = PartialHashtree.getInstance(this.reducedHashTree.getObjectAt(i));
        }
        return rv;
    }

    public ContentInfo getTimeStamp() {
        return this.timeStamp;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        if (this.digestAlgorithm != null) {
            v.add(new DERTaggedObject(false, 0, this.digestAlgorithm));
        }
        if (this.attributes != null) {
            v.add(new DERTaggedObject(false, 1, this.attributes));
        }
        if (this.reducedHashTree != null) {
            v.add(new DERTaggedObject(false, 2, this.reducedHashTree));
        }
        v.add(this.timeStamp);
        return new DERSequence(v);
    }
}
