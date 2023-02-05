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
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.BERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class AuthEnvelopedData extends ASN1Object {
    private ASN1Integer version;
    private OriginatorInfo originatorInfo;
    private ASN1Set recipientInfos;
    private EncryptedContentInfo authEncryptedContentInfo;
    private ASN1Set authAttrs;
    private ASN1OctetString mac;
    private ASN1Set unauthAttrs;

    public AuthEnvelopedData(OriginatorInfo originatorInfo, ASN1Set recipientInfos, EncryptedContentInfo authEncryptedContentInfo, ASN1Set authAttrs, ASN1OctetString mac, ASN1Set unauthAttrs) {
        this.version = new ASN1Integer(0L);
        this.originatorInfo = originatorInfo;
        this.recipientInfos = recipientInfos;
        if (this.recipientInfos.size() == 0) {
            throw new IllegalArgumentException("AuthEnvelopedData requires at least 1 RecipientInfo");
        } else {
            this.authEncryptedContentInfo = authEncryptedContentInfo;
            this.authAttrs = authAttrs;
            if (authEncryptedContentInfo.getContentType().equals(CMSObjectIdentifiers.data) || authAttrs != null && authAttrs.size() != 0) {
                this.mac = mac;
                this.unauthAttrs = unauthAttrs;
            } else {
                throw new IllegalArgumentException("authAttrs must be present with non-data content");
            }
        }
    }

    private AuthEnvelopedData(ASN1Sequence seq) {
        int index = 0;
        index = index + 1;
        ASN1Primitive tmp = seq.getObjectAt(index).toASN1Primitive();
        this.version = ASN1Integer.getInstance(tmp);
        if (!this.version.hasValue(0)) {
            throw new IllegalArgumentException("AuthEnvelopedData version number must be 0");
        } else {
            tmp = seq.getObjectAt(index++).toASN1Primitive();
            if (tmp instanceof ASN1TaggedObject) {
                this.originatorInfo = OriginatorInfo.getInstance((ASN1TaggedObject)tmp, false);
                tmp = seq.getObjectAt(index++).toASN1Primitive();
            }

            this.recipientInfos = ASN1Set.getInstance(tmp);
            if (this.recipientInfos.size() == 0) {
                throw new IllegalArgumentException("AuthEnvelopedData requires at least 1 RecipientInfo");
            } else {
                tmp = seq.getObjectAt(index++).toASN1Primitive();
                this.authEncryptedContentInfo = EncryptedContentInfo.getInstance(tmp);
                tmp = seq.getObjectAt(index++).toASN1Primitive();
                if (tmp instanceof ASN1TaggedObject) {
                    this.authAttrs = ASN1Set.getInstance((ASN1TaggedObject)tmp, false);
                    tmp = seq.getObjectAt(index++).toASN1Primitive();
                } else if (!this.authEncryptedContentInfo.getContentType().equals(CMSObjectIdentifiers.data) && (this.authAttrs == null || this.authAttrs.size() == 0)) {
                    throw new IllegalArgumentException("authAttrs must be present with non-data content");
                }

                this.mac = ASN1OctetString.getInstance(tmp);
                if (seq.size() > index) {
                    tmp = seq.getObjectAt(index).toASN1Primitive();
                    this.unauthAttrs = ASN1Set.getInstance((ASN1TaggedObject)tmp, false);
                }

            }
        }
    }

    public static AuthEnvelopedData getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static AuthEnvelopedData getInstance(Object obj) {
        if (obj instanceof AuthEnvelopedData) {
            return (AuthEnvelopedData)obj;
        } else {
            return obj != null ? new AuthEnvelopedData(ASN1Sequence.getInstance(obj)) : null;
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

    public EncryptedContentInfo getAuthEncryptedContentInfo() {
        return this.authEncryptedContentInfo;
    }

    public ASN1Set getAuthAttrs() {
        return this.authAttrs;
    }

    public ASN1OctetString getMac() {
        return this.mac;
    }

    public ASN1Set getUnauthAttrs() {
        return this.unauthAttrs;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(7);
        v.add(this.version);
        if (this.originatorInfo != null) {
            v.add(new DERTaggedObject(false, 0, this.originatorInfo));
        }

        v.add(this.recipientInfos);
        v.add(this.authEncryptedContentInfo);
        if (this.authAttrs != null) {
            v.add(new DERTaggedObject(false, 1, this.authAttrs));
        }

        v.add(this.mac);
        if (this.unauthAttrs != null) {
            v.add(new DERTaggedObject(false, 2, this.unauthAttrs));
        }

        return new BERSequence(v);
    }
}