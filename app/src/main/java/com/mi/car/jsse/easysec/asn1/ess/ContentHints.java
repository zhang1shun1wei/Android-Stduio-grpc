package com.mi.car.jsse.easysec.asn1.ess;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERUTF8String;

public class ContentHints extends ASN1Object {
    private ASN1UTF8String contentDescription;
    private ASN1ObjectIdentifier contentType;

    public static ContentHints getInstance(Object o) {
        if (o instanceof ContentHints) {
            return (ContentHints)o;
        } else {
            return o != null ? new ContentHints(ASN1Sequence.getInstance(o)) : null;
        }
    }

    private ContentHints(ASN1Sequence seq) {
        ASN1Encodable field = seq.getObjectAt(0);
        if (field.toASN1Primitive() instanceof ASN1UTF8String) {
            this.contentDescription = ASN1UTF8String.getInstance(field);
            this.contentType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
        } else {
            this.contentType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        }

    }

    public ContentHints(ASN1ObjectIdentifier contentType) {
        this.contentType = contentType;
        this.contentDescription = null;
    }

    public ContentHints(ASN1ObjectIdentifier contentType, ASN1UTF8String contentDescription) {
        this.contentType = contentType;
        this.contentDescription = contentDescription;
    }

    public ASN1ObjectIdentifier getContentType() {
        return this.contentType;
    }

    /** @deprecated */
    public DERUTF8String getContentDescription() {
        return null != this.contentDescription && !(this.contentDescription instanceof DERUTF8String) ? new DERUTF8String(this.contentDescription.getString()) : (DERUTF8String)this.contentDescription;
    }

    public ASN1UTF8String getContentDescriptionUTF8() {
        return this.contentDescription;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        if (this.contentDescription != null) {
            v.add(this.contentDescription);
        }

        v.add(this.contentType);
        return new DERSequence(v);
    }
}
