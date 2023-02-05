//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Boolean;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1IA5String;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.DERIA5String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERUTF8String;

public class MetaData extends ASN1Object {
    private ASN1Boolean hashProtected;
    private ASN1UTF8String fileName;
    private ASN1IA5String mediaType;
    private Attributes otherMetaData;

    public MetaData(ASN1Boolean hashProtected, ASN1UTF8String fileName, ASN1IA5String mediaType, Attributes otherMetaData) {
        this.hashProtected = hashProtected;
        this.fileName = fileName;
        this.mediaType = mediaType;
        this.otherMetaData = otherMetaData;
    }

    private MetaData(ASN1Sequence seq) {
        this.hashProtected = ASN1Boolean.getInstance(seq.getObjectAt(0));
        int index = 1;
        if (index < seq.size() && seq.getObjectAt(index) instanceof ASN1UTF8String) {
            this.fileName = ASN1UTF8String.getInstance(seq.getObjectAt(index++));
        }

        if (index < seq.size() && seq.getObjectAt(index) instanceof ASN1IA5String) {
            this.mediaType = ASN1IA5String.getInstance(seq.getObjectAt(index++));
        }

        if (index < seq.size()) {
            this.otherMetaData = Attributes.getInstance(seq.getObjectAt(index++));
        }

    }

    public static MetaData getInstance(Object obj) {
        if (obj instanceof MetaData) {
            return (MetaData)obj;
        } else {
            return obj != null ? new MetaData(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.hashProtected);
        if (this.fileName != null) {
            v.add(this.fileName);
        }

        if (this.mediaType != null) {
            v.add(this.mediaType);
        }

        if (this.otherMetaData != null) {
            v.add(this.otherMetaData);
        }

        return new DERSequence(v);
    }

    public boolean isHashProtected() {
        return this.hashProtected.isTrue();
    }

    /** @deprecated */
    public DERUTF8String getFileName() {
        return null != this.fileName && !(this.fileName instanceof DERUTF8String) ? new DERUTF8String(this.fileName.getString()) : (DERUTF8String)this.fileName;
    }

    public ASN1UTF8String getFileNameUTF8() {
        return this.fileName;
    }

    /** @deprecated */
    public DERIA5String getMediaType() {
        return null != this.mediaType && !(this.mediaType instanceof DERIA5String) ? new DERIA5String(this.mediaType.getString(), false) : (DERIA5String)this.mediaType;
    }

    public ASN1IA5String getMediaTypeIA5() {
        return this.mediaType;
    }

    public Attributes getOtherMetaData() {
        return this.otherMetaData;
    }
}
