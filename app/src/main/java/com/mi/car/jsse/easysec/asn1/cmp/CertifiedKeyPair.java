//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.crmf.EncryptedKey;
import com.mi.car.jsse.easysec.asn1.crmf.EncryptedValue;
import com.mi.car.jsse.easysec.asn1.crmf.PKIPublicationInfo;

public class CertifiedKeyPair extends ASN1Object {
    private final CertOrEncCert certOrEncCert;
    private EncryptedKey privateKey;
    private PKIPublicationInfo publicationInfo;

    private CertifiedKeyPair(ASN1Sequence seq) {
        this.certOrEncCert = CertOrEncCert.getInstance(seq.getObjectAt(0));
        if (seq.size() >= 2) {
            if (seq.size() == 2) {
                ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
                if (tagged.getTagNo() == 0) {
                    this.privateKey = EncryptedKey.getInstance(tagged.getObject());
                } else {
                    this.publicationInfo = PKIPublicationInfo.getInstance(tagged.getObject());
                }
            } else {
                this.privateKey = EncryptedKey.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(1)).getObject());
                this.publicationInfo = PKIPublicationInfo.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(2)).getObject());
            }
        }

    }

    public CertifiedKeyPair(CertOrEncCert certOrEncCert) {
        this(certOrEncCert, (EncryptedKey)((EncryptedKey)null), (PKIPublicationInfo)null);
    }

    public CertifiedKeyPair(CertOrEncCert certOrEncCert, EncryptedKey privateKey, PKIPublicationInfo publicationInfo) {
        if (certOrEncCert == null) {
            throw new IllegalArgumentException("'certOrEncCert' cannot be null");
        } else {
            this.certOrEncCert = certOrEncCert;
            this.privateKey = privateKey;
            this.publicationInfo = publicationInfo;
        }
    }

    public CertifiedKeyPair(CertOrEncCert certOrEncCert, EncryptedValue privateKey, PKIPublicationInfo publicationInfo) {
        if (certOrEncCert == null) {
            throw new IllegalArgumentException("'certOrEncCert' cannot be null");
        } else {
            this.certOrEncCert = certOrEncCert;
            this.privateKey = privateKey != null ? new EncryptedKey(privateKey) : null;
            this.publicationInfo = publicationInfo;
        }
    }

    public static CertifiedKeyPair getInstance(Object o) {
        if (o instanceof CertifiedKeyPair) {
            return (CertifiedKeyPair)o;
        } else {
            return o != null ? new CertifiedKeyPair(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public CertOrEncCert getCertOrEncCert() {
        return this.certOrEncCert;
    }

    public EncryptedKey getPrivateKey() {
        return this.privateKey;
    }

    public PKIPublicationInfo getPublicationInfo() {
        return this.publicationInfo;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.certOrEncCert);
        if (this.privateKey != null) {
            v.add(new DERTaggedObject(true, 0, this.privateKey));
        }

        if (this.publicationInfo != null) {
            v.add(new DERTaggedObject(true, 1, this.publicationInfo));
        }

        return new DERSequence(v);
    }
}
