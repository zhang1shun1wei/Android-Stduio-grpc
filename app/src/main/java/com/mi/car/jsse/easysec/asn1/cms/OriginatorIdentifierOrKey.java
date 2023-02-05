//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.SubjectKeyIdentifier;

public class OriginatorIdentifierOrKey extends ASN1Object implements ASN1Choice {
    private ASN1Encodable id;

    public OriginatorIdentifierOrKey(IssuerAndSerialNumber id) {
        this.id = id;
    }

    /** @deprecated */
    public OriginatorIdentifierOrKey(ASN1OctetString id) {
        this(new SubjectKeyIdentifier(id.getOctets()));
    }

    public OriginatorIdentifierOrKey(SubjectKeyIdentifier id) {
        this.id = new DERTaggedObject(false, 0, id);
    }

    public OriginatorIdentifierOrKey(OriginatorPublicKey id) {
        this.id = new DERTaggedObject(false, 1, id);
    }

    /** @deprecated */
    public OriginatorIdentifierOrKey(ASN1Primitive id) {
        this.id = id;
    }

    public static OriginatorIdentifierOrKey getInstance(ASN1TaggedObject o, boolean explicit) {
        if (!explicit) {
            throw new IllegalArgumentException("Can't implicitly tag OriginatorIdentifierOrKey");
        } else {
            return getInstance(o.getObject());
        }
    }

    public static OriginatorIdentifierOrKey getInstance(Object o) {
        if (o != null && !(o instanceof OriginatorIdentifierOrKey)) {
            if (!(o instanceof IssuerAndSerialNumber) && !(o instanceof ASN1Sequence)) {
                if (o instanceof ASN1TaggedObject) {
                    ASN1TaggedObject tagged = (ASN1TaggedObject)o;
                    if (tagged.getTagNo() == 0) {
                        return new OriginatorIdentifierOrKey(SubjectKeyIdentifier.getInstance(tagged, false));
                    }

                    if (tagged.getTagNo() == 1) {
                        return new OriginatorIdentifierOrKey(OriginatorPublicKey.getInstance(tagged, false));
                    }
                }

                throw new IllegalArgumentException("Invalid OriginatorIdentifierOrKey: " + o.getClass().getName());
            } else {
                return new OriginatorIdentifierOrKey(IssuerAndSerialNumber.getInstance(o));
            }
        } else {
            return (OriginatorIdentifierOrKey)o;
        }
    }

    public ASN1Encodable getId() {
        return this.id;
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber() {
        return this.id instanceof IssuerAndSerialNumber ? (IssuerAndSerialNumber)this.id : null;
    }

    public SubjectKeyIdentifier getSubjectKeyIdentifier() {
        return this.id instanceof ASN1TaggedObject && ((ASN1TaggedObject)this.id).getTagNo() == 0 ? SubjectKeyIdentifier.getInstance((ASN1TaggedObject)this.id, false) : null;
    }

    public OriginatorPublicKey getOriginatorKey() {
        return this.id instanceof ASN1TaggedObject && ((ASN1TaggedObject)this.id).getTagNo() == 1 ? OriginatorPublicKey.getInstance((ASN1TaggedObject)this.id, false) : null;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.id.toASN1Primitive();
    }
}
