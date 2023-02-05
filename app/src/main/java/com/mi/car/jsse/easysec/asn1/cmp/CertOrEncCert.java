//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.crmf.EncryptedKey;
import com.mi.car.jsse.easysec.asn1.crmf.EncryptedValue;

public class CertOrEncCert extends ASN1Object implements ASN1Choice {
    private CMPCertificate certificate;
    private EncryptedKey encryptedKey;

    private CertOrEncCert(ASN1TaggedObject tagged) {
        if (tagged.getTagNo() == 0) {
            this.certificate = CMPCertificate.getInstance(tagged.getObject());
        } else {
            if (tagged.getTagNo() != 1) {
                throw new IllegalArgumentException("unknown tag: " + tagged.getTagNo());
            }

            this.encryptedKey = EncryptedKey.getInstance(tagged.getObject());
        }

    }

    public CertOrEncCert(CMPCertificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("'certificate' cannot be null");
        } else {
            this.certificate = certificate;
        }
    }

    public CertOrEncCert(EncryptedValue encryptedCert) {
        if (encryptedCert == null) {
            throw new IllegalArgumentException("'encryptedCert' cannot be null");
        } else {
            this.encryptedKey = new EncryptedKey(encryptedCert);
        }
    }

    public CertOrEncCert(EncryptedKey encryptedKey) {
        if (encryptedKey == null) {
            throw new IllegalArgumentException("'encryptedKey' cannot be null");
        } else {
            this.encryptedKey = encryptedKey;
        }
    }

    public static CertOrEncCert getInstance(Object o) {
        if (o instanceof CertOrEncCert) {
            return (CertOrEncCert)o;
        } else {
            return o instanceof ASN1TaggedObject ? new CertOrEncCert((ASN1TaggedObject)o) : null;
        }
    }

    public CMPCertificate getCertificate() {
        return this.certificate;
    }

    public EncryptedKey getEncryptedCert() {
        return this.encryptedKey;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.certificate != null ? new DERTaggedObject(true, 0, this.certificate) : new DERTaggedObject(true, 1, this.encryptedKey);
    }
}
