//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.AttributeCertificate;
import com.mi.car.jsse.easysec.asn1.x509.Certificate;
import java.io.IOException;

public class CMPCertificate extends ASN1Object implements ASN1Choice {
    private Certificate x509v3PKCert;
    private int otherTagValue;
    private ASN1Object otherCert;

    /** @deprecated */
    public CMPCertificate(AttributeCertificate x509v2AttrCert) {
        this(1, x509v2AttrCert);
    }

    public CMPCertificate(int type, ASN1Object otherCert) {
        this.otherTagValue = type;
        this.otherCert = otherCert;
    }

    public CMPCertificate(Certificate x509v3PKCert) {
        if (x509v3PKCert.getVersionNumber() != 3) {
            throw new IllegalArgumentException("only version 3 certificates allowed");
        } else {
            this.x509v3PKCert = x509v3PKCert;
        }
    }

    public static CMPCertificate getInstance(ASN1TaggedObject ato, boolean isExplicit) {
        if (ato != null) {
            if (isExplicit) {
                return getInstance(ato.getObject());
            } else {
                throw new IllegalArgumentException("tag must be explicit");
            }
        } else {
            return null;
        }
    }

    public static CMPCertificate getInstance(Object o) {
        if (o != null && !(o instanceof CMPCertificate)) {
            if (o instanceof byte[]) {
                try {
                    o = ASN1Primitive.fromByteArray((byte[])((byte[])o));
                } catch (IOException var2) {
                    throw new IllegalArgumentException("Invalid encoding in CMPCertificate");
                }
            }

            if (o instanceof ASN1Sequence) {
                return new CMPCertificate(Certificate.getInstance(o));
            } else if (o instanceof ASN1TaggedObject) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject)o;
                return new CMPCertificate(taggedObject.getTagNo(), taggedObject.getObject());
            } else {
                throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
            }
        } else {
            return (CMPCertificate)o;
        }
    }

    public boolean isX509v3PKCert() {
        return this.x509v3PKCert != null;
    }

    public Certificate getX509v3PKCert() {
        return this.x509v3PKCert;
    }

    /** @deprecated */
    public AttributeCertificate getX509v2AttrCert() {
        return AttributeCertificate.getInstance(this.otherCert);
    }

    public int getOtherCertTag() {
        return this.otherTagValue;
    }

    public ASN1Object getOtherCert() {
        return this.otherCert;
    }

    public ASN1Primitive toASN1Primitive() {
        return (ASN1Primitive)(this.otherCert != null ? new DERTaggedObject(true, this.otherTagValue, this.otherCert) : this.x509v3PKCert.toASN1Primitive());
    }
}