//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1IA5String;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.BERSequence;
import com.mi.car.jsse.easysec.asn1.DERIA5String;

public class TimeStampedData extends ASN1Object {
    private ASN1Integer version;
    private ASN1IA5String dataUri;
    private MetaData metaData;
    private ASN1OctetString content;
    private Evidence temporalEvidence;

    public TimeStampedData(ASN1IA5String dataUri, MetaData metaData, ASN1OctetString content, Evidence temporalEvidence) {
        this.version = new ASN1Integer(1L);
        this.dataUri = dataUri;
        this.metaData = metaData;
        this.content = content;
        this.temporalEvidence = temporalEvidence;
    }

    private TimeStampedData(ASN1Sequence seq) {
        this.version = ASN1Integer.getInstance(seq.getObjectAt(0));
        int index = 1;
        if (seq.getObjectAt(index) instanceof ASN1IA5String) {
            this.dataUri = ASN1IA5String.getInstance(seq.getObjectAt(index++));
        }

        if (seq.getObjectAt(index) instanceof MetaData || seq.getObjectAt(index) instanceof ASN1Sequence) {
            this.metaData = MetaData.getInstance(seq.getObjectAt(index++));
        }

        if (seq.getObjectAt(index) instanceof ASN1OctetString) {
            this.content = ASN1OctetString.getInstance(seq.getObjectAt(index++));
        }

        this.temporalEvidence = Evidence.getInstance(seq.getObjectAt(index));
    }

    public static TimeStampedData getInstance(Object obj) {
        return obj != null && !(obj instanceof TimeStampedData) ? new TimeStampedData(ASN1Sequence.getInstance(obj)) : (TimeStampedData)obj;
    }

    /** @deprecated */
    public DERIA5String getDataUri() {
        return null != this.dataUri && !(this.dataUri instanceof DERIA5String) ? new DERIA5String(this.dataUri.getString(), false) : (DERIA5String)this.dataUri;
    }

    public ASN1IA5String getDataUriIA5() {
        return this.dataUri;
    }

    public MetaData getMetaData() {
        return this.metaData;
    }

    public ASN1OctetString getContent() {
        return this.content;
    }

    public Evidence getTemporalEvidence() {
        return this.temporalEvidence;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(5);
        v.add(this.version);
        if (this.dataUri != null) {
            v.add(this.dataUri);
        }

        if (this.metaData != null) {
            v.add(this.metaData);
        }

        if (this.content != null) {
            v.add(this.content);
        }

        v.add(this.temporalEvidence);
        return new BERSequence(v);
    }
}
