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
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.BERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.util.Enumeration;

public class EnvelopedData extends ASN1Object {
    private ASN1Integer version;
    private OriginatorInfo originatorInfo;
    private ASN1Set recipientInfos;
    private EncryptedContentInfo encryptedContentInfo;
    private ASN1Set unprotectedAttrs;

    public EnvelopedData(OriginatorInfo originatorInfo, ASN1Set recipientInfos, EncryptedContentInfo encryptedContentInfo, ASN1Set unprotectedAttrs) {
        this.version = new ASN1Integer((long)calculateVersion(originatorInfo, recipientInfos, unprotectedAttrs));
        this.originatorInfo = originatorInfo;
        this.recipientInfos = recipientInfos;
        this.encryptedContentInfo = encryptedContentInfo;
        this.unprotectedAttrs = unprotectedAttrs;
    }

    public EnvelopedData(OriginatorInfo originatorInfo, ASN1Set recipientInfos, EncryptedContentInfo encryptedContentInfo, Attributes unprotectedAttrs) {
        this.version = new ASN1Integer((long)calculateVersion(originatorInfo, recipientInfos, ASN1Set.getInstance(unprotectedAttrs)));
        this.originatorInfo = originatorInfo;
        this.recipientInfos = recipientInfos;
        this.encryptedContentInfo = encryptedContentInfo;
        this.unprotectedAttrs = ASN1Set.getInstance(unprotectedAttrs);
    }

    private EnvelopedData(ASN1Sequence seq) {
        int index = 0;
        index = index + 1;
        this.version = (ASN1Integer)seq.getObjectAt(index);
        Object tmp = seq.getObjectAt(index++);
        if (tmp instanceof ASN1TaggedObject) {
            this.originatorInfo = OriginatorInfo.getInstance((ASN1TaggedObject)tmp, false);
            tmp = seq.getObjectAt(index++);
        }

        this.recipientInfos = ASN1Set.getInstance(tmp);
        this.encryptedContentInfo = EncryptedContentInfo.getInstance(seq.getObjectAt(index++));
        if (seq.size() > index) {
            this.unprotectedAttrs = ASN1Set.getInstance((ASN1TaggedObject)seq.getObjectAt(index), false);
        }

    }

    public static EnvelopedData getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static EnvelopedData getInstance(Object obj) {
        if (obj instanceof EnvelopedData) {
            return (EnvelopedData)obj;
        } else {
            return obj != null ? new EnvelopedData(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public OriginatorInfo getOriginatorInfo() {
        return this.originatorInfo;
    }

    public ASN1Set getRecipientInfos() {
        return this.recipientInfos;
    }

    public EncryptedContentInfo getEncryptedContentInfo() {
        return this.encryptedContentInfo;
    }

    public ASN1Set getUnprotectedAttrs() {
        return this.unprotectedAttrs;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(5);
        v.add(this.version);
        if (this.originatorInfo != null) {
            v.add(new DERTaggedObject(false, 0, this.originatorInfo));
        }

        v.add(this.recipientInfos);
        v.add(this.encryptedContentInfo);
        if (this.unprotectedAttrs != null) {
            v.add(new DERTaggedObject(false, 1, this.unprotectedAttrs));
        }

        return new BERSequence(v);
    }

    public static int calculateVersion(OriginatorInfo originatorInfo, ASN1Set recipientInfos, ASN1Set unprotectedAttrs) {
        byte version;
        if (originatorInfo == null && unprotectedAttrs == null) {
            version = 0;
            Enumeration e = recipientInfos.getObjects();

            while(e.hasMoreElements()) {
                RecipientInfo ri = RecipientInfo.getInstance(e.nextElement());
                if (!ri.getVersion().hasValue(version)) {
                    version = 2;
                    break;
                }
            }
        } else {
            version = 2;
        }

        return version;
    }
}
