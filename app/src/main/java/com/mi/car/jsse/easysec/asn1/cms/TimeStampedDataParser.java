//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1IA5String;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1OctetStringParser;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1SequenceParser;
import com.mi.car.jsse.easysec.asn1.DERIA5String;
import java.io.IOException;

public class TimeStampedDataParser {
    private ASN1Integer version;
    private ASN1IA5String dataUri;
    private MetaData metaData;
    private ASN1OctetStringParser content;
    private Evidence temporalEvidence;
    private ASN1SequenceParser parser;

    private TimeStampedDataParser(ASN1SequenceParser parser) throws IOException {
        this.parser = parser;
        this.version = ASN1Integer.getInstance(parser.readObject());
        ASN1Encodable obj = parser.readObject();
        if (obj instanceof ASN1IA5String) {
            this.dataUri = ASN1IA5String.getInstance(obj);
            obj = parser.readObject();
        }

        if (obj instanceof MetaData || obj instanceof ASN1SequenceParser) {
            this.metaData = MetaData.getInstance(obj.toASN1Primitive());
            obj = parser.readObject();
        }

        if (obj instanceof ASN1OctetStringParser) {
            this.content = (ASN1OctetStringParser)obj;
        }

    }

    public static TimeStampedDataParser getInstance(Object obj) throws IOException {
        if (obj instanceof ASN1Sequence) {
            return new TimeStampedDataParser(((ASN1Sequence)obj).parser());
        } else {
            return obj instanceof ASN1SequenceParser ? new TimeStampedDataParser((ASN1SequenceParser)obj) : null;
        }
    }

    public int getVersion() {
        return this.version.getValue().intValue();
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

    public ASN1OctetStringParser getContent() {
        return this.content;
    }

    public Evidence getTemporalEvidence() throws IOException {
        if (this.temporalEvidence == null) {
            this.temporalEvidence = Evidence.getInstance(this.parser.readObject().toASN1Primitive());
        }

        return this.temporalEvidence;
    }
}
