//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.BERSequence;
import com.mi.car.jsse.easysec.asn1.BERSet;
import com.mi.car.jsse.easysec.asn1.BERTaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.DLSequence;
import java.util.Enumeration;

public class SignedData extends ASN1Object {
    private static final ASN1Integer VERSION_1 = new ASN1Integer(1L);
    private static final ASN1Integer VERSION_3 = new ASN1Integer(3L);
    private static final ASN1Integer VERSION_4 = new ASN1Integer(4L);
    private static final ASN1Integer VERSION_5 = new ASN1Integer(5L);
    private final ASN1Integer version;
    private final ASN1Set digestAlgorithms;
    private final ContentInfo contentInfo;
    private final ASN1Set signerInfos;
    private final boolean digsBer;
    private final boolean sigsBer;
    private ASN1Set certificates;
    private ASN1Set crls;
    private boolean certsBer;
    private boolean crlsBer;

    public static SignedData getInstance(Object o) {
        if (o instanceof SignedData) {
            return (SignedData)o;
        } else {
            return o != null ? new SignedData(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public SignedData(ASN1Set digestAlgorithms, ContentInfo contentInfo, ASN1Set certificates, ASN1Set crls, ASN1Set signerInfos) {
        this.version = this.calculateVersion(contentInfo.getContentType(), certificates, crls, signerInfos);
        this.digestAlgorithms = digestAlgorithms;
        this.contentInfo = contentInfo;
        this.certificates = certificates;
        this.crls = crls;
        this.signerInfos = signerInfos;
        this.digsBer = digestAlgorithms instanceof BERSet;
        this.crlsBer = crls instanceof BERSet;
        this.certsBer = certificates instanceof BERSet;
        this.sigsBer = signerInfos instanceof BERSet;
    }

    private ASN1Integer calculateVersion(ASN1ObjectIdentifier contentOid, ASN1Set certs, ASN1Set crls, ASN1Set signerInfs) {
        boolean otherCert = false;
        boolean otherCrl = false;
        boolean attrCertV1Found = false;
        boolean attrCertV2Found = false;
        Enumeration en;
        Object obj;
        if (certs != null) {
            en = certs.getObjects();

            while(en.hasMoreElements()) {
                obj = en.nextElement();
                if (obj instanceof ASN1TaggedObject) {
                    ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(obj);
                    if (tagged.getTagNo() == 1) {
                        attrCertV1Found = true;
                    } else if (tagged.getTagNo() == 2) {
                        attrCertV2Found = true;
                    } else if (tagged.getTagNo() == 3) {
                        otherCert = true;
                    }
                }
            }
        }

        if (otherCert) {
            return new ASN1Integer(5L);
        } else {
            if (crls != null) {
                en = crls.getObjects();

                while(en.hasMoreElements()) {
                    obj = en.nextElement();
                    if (obj instanceof ASN1TaggedObject) {
                        otherCrl = true;
                    }
                }
            }

            if (otherCrl) {
                return VERSION_5;
            } else if (attrCertV2Found) {
                return VERSION_4;
            } else if (attrCertV1Found) {
                return VERSION_3;
            } else if (this.checkForVersion3(signerInfs)) {
                return VERSION_3;
            } else {
                return !CMSObjectIdentifiers.data.equals(contentOid) ? VERSION_3 : VERSION_1;
            }
        }
    }

    private boolean checkForVersion3(ASN1Set signerInfs) {
        Enumeration e = signerInfs.getObjects();

        SignerInfo s;
        do {
            if (!e.hasMoreElements()) {
                return false;
            }

            s = SignerInfo.getInstance(e.nextElement());
        } while(!s.getVersion().hasValue(3));

        return true;
    }

    private SignedData(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.version = ASN1Integer.getInstance(e.nextElement());
        this.digestAlgorithms = (ASN1Set)e.nextElement();
        this.contentInfo = ContentInfo.getInstance(e.nextElement());
        ASN1Set sigInfs = null;

        while(e.hasMoreElements()) {
            ASN1Primitive o = (ASN1Primitive)e.nextElement();
            if (o instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject)o;
                switch(tagged.getTagNo()) {
                    case 0:
                        this.certsBer = tagged instanceof BERTaggedObject;
                        this.certificates = ASN1Set.getInstance(tagged, false);
                        break;
                    case 1:
                        this.crlsBer = tagged instanceof BERTaggedObject;
                        this.crls = ASN1Set.getInstance(tagged, false);
                        break;
                    default:
                        throw new IllegalArgumentException("unknown tag value " + tagged.getTagNo());
                }
            } else {
                if (!(o instanceof ASN1Set)) {
                    throw new IllegalArgumentException("SET expected, not encountered");
                }

                sigInfs = (ASN1Set)o;
            }
        }

        if (sigInfs == null) {
            throw new IllegalArgumentException("signerInfos not set");
        } else {
            this.signerInfos = sigInfs;
            this.digsBer = this.digestAlgorithms instanceof BERSet;
            this.sigsBer = this.signerInfos instanceof BERSet;
        }
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public ASN1Set getDigestAlgorithms() {
        return this.digestAlgorithms;
    }

    public ContentInfo getEncapContentInfo() {
        return this.contentInfo;
    }

    public ASN1Set getCertificates() {
        return this.certificates;
    }

    public ASN1Set getCRLs() {
        return this.crls;
    }

    public ASN1Set getSignerInfos() {
        return this.signerInfos;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(6);
        v.add(this.version);
        v.add(this.digestAlgorithms);
        v.add(this.contentInfo);
        if (this.certificates != null) {
            if (this.certsBer) {
                v.add(new BERTaggedObject(false, 0, this.certificates));
            } else {
                v.add(new DERTaggedObject(false, 0, this.certificates));
            }
        }

        if (this.crls != null) {
            if (this.crlsBer) {
                v.add(new BERTaggedObject(false, 1, this.crls));
            } else {
                v.add(new DERTaggedObject(false, 1, this.crls));
            }
        }

        v.add(this.signerInfos);
        return (ASN1Primitive)(this.contentInfo.isDefiniteLength() && !this.digsBer && !this.sigsBer && !this.crlsBer && !this.certsBer ? new DLSequence(v) : new BERSequence(v));
    }
}
