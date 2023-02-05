//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.BERSequence;
import com.mi.car.jsse.easysec.asn1.BERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class EncryptedContentInfo extends ASN1Object {
    private ASN1ObjectIdentifier contentType;
    private AlgorithmIdentifier contentEncryptionAlgorithm;
    private ASN1OctetString encryptedContent;

    public EncryptedContentInfo(ASN1ObjectIdentifier contentType, AlgorithmIdentifier contentEncryptionAlgorithm, ASN1OctetString encryptedContent) {
        this.contentType = contentType;
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
        this.encryptedContent = encryptedContent;
    }

    private EncryptedContentInfo(ASN1Sequence seq) {
        if (seq.size() < 2) {
            throw new IllegalArgumentException("Truncated Sequence Found");
        } else {
            this.contentType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
            this.contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            if (seq.size() > 2) {
                this.encryptedContent = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(2), false);
            }

        }
    }

    public static EncryptedContentInfo getInstance(Object obj) {
        if (obj instanceof EncryptedContentInfo) {
            return (EncryptedContentInfo)obj;
        } else {
            return obj != null ? new EncryptedContentInfo(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1ObjectIdentifier getContentType() {
        return this.contentType;
    }

    public AlgorithmIdentifier getContentEncryptionAlgorithm() {
        return this.contentEncryptionAlgorithm;
    }

    public ASN1OctetString getEncryptedContent() {
        return this.encryptedContent;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.contentType);
        v.add(this.contentEncryptionAlgorithm);
        if (this.encryptedContent != null) {
            v.add(new BERTaggedObject(false, 0, this.encryptedContent));
        }

        return new BERSequence(v);
    }
}
