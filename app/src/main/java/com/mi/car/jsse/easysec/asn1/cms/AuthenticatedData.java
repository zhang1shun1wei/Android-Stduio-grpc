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
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import java.util.Enumeration;

public class AuthenticatedData extends ASN1Object {
    private ASN1Integer version;
    private OriginatorInfo originatorInfo;
    private ASN1Set recipientInfos;
    private AlgorithmIdentifier macAlgorithm;
    private AlgorithmIdentifier digestAlgorithm;
    private ContentInfo encapsulatedContentInfo;
    private ASN1Set authAttrs;
    private ASN1OctetString mac;
    private ASN1Set unauthAttrs;

    public AuthenticatedData(OriginatorInfo originatorInfo, ASN1Set recipientInfos, AlgorithmIdentifier macAlgorithm, AlgorithmIdentifier digestAlgorithm, ContentInfo encapsulatedContent, ASN1Set authAttrs, ASN1OctetString mac, ASN1Set unauthAttrs) {
        if (digestAlgorithm == null && authAttrs == null || digestAlgorithm != null && authAttrs != null) {
            this.version = new ASN1Integer((long)calculateVersion(originatorInfo));
            this.originatorInfo = originatorInfo;
            this.macAlgorithm = macAlgorithm;
            this.digestAlgorithm = digestAlgorithm;
            this.recipientInfos = recipientInfos;
            this.encapsulatedContentInfo = encapsulatedContent;
            this.authAttrs = authAttrs;
            this.mac = mac;
            this.unauthAttrs = unauthAttrs;
        } else {
            throw new IllegalArgumentException("digestAlgorithm and authAttrs must be set together");
        }
    }

    private AuthenticatedData(ASN1Sequence seq) {
        int index = 0;
        index = index + 1;
        this.version = (ASN1Integer)seq.getObjectAt(index);
        Object tmp = seq.getObjectAt(index++);
        if (tmp instanceof ASN1TaggedObject) {
            this.originatorInfo = OriginatorInfo.getInstance((ASN1TaggedObject)tmp, false);
            tmp = seq.getObjectAt(index++);
        }

        this.recipientInfos = ASN1Set.getInstance(tmp);
        this.macAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));
        tmp = seq.getObjectAt(index++);
        if (tmp instanceof ASN1TaggedObject) {
            this.digestAlgorithm = AlgorithmIdentifier.getInstance((ASN1TaggedObject)tmp, false);
            tmp = seq.getObjectAt(index++);
        }

        this.encapsulatedContentInfo = ContentInfo.getInstance(tmp);
        tmp = seq.getObjectAt(index++);
        if (tmp instanceof ASN1TaggedObject) {
            this.authAttrs = ASN1Set.getInstance((ASN1TaggedObject)tmp, false);
            tmp = seq.getObjectAt(index++);
        }

        this.mac = ASN1OctetString.getInstance(tmp);
        if (seq.size() > index) {
            this.unauthAttrs = ASN1Set.getInstance((ASN1TaggedObject)seq.getObjectAt(index), false);
        }

    }

    public static AuthenticatedData getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static AuthenticatedData getInstance(Object obj) {
        if (obj instanceof AuthenticatedData) {
            return (AuthenticatedData)obj;
        } else {
            return obj != null ? new AuthenticatedData(ASN1Sequence.getInstance(obj)) : null;
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

    public AlgorithmIdentifier getMacAlgorithm() {
        return this.macAlgorithm;
    }

    public AlgorithmIdentifier getDigestAlgorithm() {
        return this.digestAlgorithm;
    }

    public ContentInfo getEncapsulatedContentInfo() {
        return this.encapsulatedContentInfo;
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
        ASN1EncodableVector v = new ASN1EncodableVector(9);
        v.add(this.version);
        if (this.originatorInfo != null) {
            v.add(new DERTaggedObject(false, 0, this.originatorInfo));
        }

        v.add(this.recipientInfos);
        v.add(this.macAlgorithm);
        if (this.digestAlgorithm != null) {
            v.add(new DERTaggedObject(false, 1, this.digestAlgorithm));
        }

        v.add(this.encapsulatedContentInfo);
        if (this.authAttrs != null) {
            v.add(new DERTaggedObject(false, 2, this.authAttrs));
        }

        v.add(this.mac);
        if (this.unauthAttrs != null) {
            v.add(new DERTaggedObject(false, 3, this.unauthAttrs));
        }

        return new BERSequence(v);
    }

    public static int calculateVersion(OriginatorInfo origInfo) {
        if (origInfo == null) {
            return 0;
        } else {
            int ver = 0;
            Enumeration e = origInfo.getCertificates().getObjects();

            Object obj;
            ASN1TaggedObject tag;
            while(e.hasMoreElements()) {
                obj = e.nextElement();
                if (obj instanceof ASN1TaggedObject) {
                    tag = (ASN1TaggedObject)obj;
                    if (tag.getTagNo() == 2) {
                        ver = 1;
                    } else if (tag.getTagNo() == 3) {
                        ver = 3;
                        break;
                    }
                }
            }

            if (origInfo.getCRLs() != null) {
                e = origInfo.getCRLs().getObjects();

                while(e.hasMoreElements()) {
                    obj = e.nextElement();
                    if (obj instanceof ASN1TaggedObject) {
                        tag = (ASN1TaggedObject)obj;
                        if (tag.getTagNo() == 1) {
                            ver = 3;
                            break;
                        }
                    }
                }
            }

            return ver;
        }
    }
}
