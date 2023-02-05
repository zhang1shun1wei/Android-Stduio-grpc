//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.BERSequence;
import com.mi.car.jsse.easysec.asn1.BERTaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DLSequence;
import com.mi.car.jsse.easysec.asn1.DLTaggedObject;

public class ContentInfo extends ASN1Object implements CMSObjectIdentifiers {
    private final ASN1ObjectIdentifier contentType;
    private final ASN1Encodable content;
    private final boolean isDefiniteLength;

    public static ContentInfo getInstance(Object obj) {
        if (obj instanceof ContentInfo) {
            return (ContentInfo)obj;
        } else {
            return obj != null ? new ContentInfo(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public static ContentInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    private ContentInfo(ASN1Sequence seq) {
        if (seq.size() >= 1 && seq.size() <= 2) {
            this.contentType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
            if (seq.size() > 1) {
                ASN1TaggedObject tagged = (ASN1TaggedObject)seq.getObjectAt(1);
                if (!tagged.isExplicit() || tagged.getTagNo() != 0) {
                    throw new IllegalArgumentException("Bad tag for 'content'");
                }

                this.content = tagged.getObject();
            } else {
                this.content = null;
            }

            this.isDefiniteLength = !(seq instanceof BERSequence);
        } else {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
    }

    public ContentInfo(ASN1ObjectIdentifier contentType, ASN1Encodable content) {
        this.contentType = contentType;
        this.content = content;
        if (content != null) {
            ASN1Primitive prim = content.toASN1Primitive();
            this.isDefiniteLength = prim instanceof DEROctetString || prim instanceof DLSequence || prim instanceof DERSequence;
        } else {
            this.isDefiniteLength = true;
        }

    }

    public ASN1ObjectIdentifier getContentType() {
        return this.contentType;
    }

    public ASN1Encodable getContent() {
        return this.content;
    }

    public boolean isDefiniteLength() {
        return this.isDefiniteLength;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.contentType);
        if (this.content != null) {
            if (this.isDefiniteLength) {
                v.add(new DLTaggedObject(0, this.content));
            } else {
                v.add(new BERTaggedObject(0, this.content));
            }
        }

        return (ASN1Primitive)(this.isDefiniteLength ? new DLSequence(v) : new BERSequence(v));
    }
}
