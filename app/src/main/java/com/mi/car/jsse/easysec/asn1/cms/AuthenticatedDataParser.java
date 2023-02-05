//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1SequenceParser;
import com.mi.car.jsse.easysec.asn1.ASN1SetParser;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser;
import com.mi.car.jsse.easysec.asn1.ASN1Util;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import java.io.IOException;

public class AuthenticatedDataParser {
    private ASN1SequenceParser seq;
    private ASN1Integer version;
    private ASN1Encodable nextObject;
    private boolean originatorInfoCalled;

    public AuthenticatedDataParser(ASN1SequenceParser seq) throws IOException {
        this.seq = seq;
        this.version = ASN1Integer.getInstance(seq.readObject());
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public OriginatorInfo getOriginatorInfo() throws IOException {
        this.originatorInfoCalled = true;
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }

        if (this.nextObject instanceof ASN1TaggedObjectParser) {
            ASN1TaggedObjectParser o = (ASN1TaggedObjectParser)this.nextObject;
            if (o.hasContextTag(0)) {
                ASN1SequenceParser originatorInfo = (ASN1SequenceParser)o.parseBaseUniversal(false, 16);
                this.nextObject = null;
                return OriginatorInfo.getInstance(originatorInfo.getLoadedObject());
            }
        }

        return null;
    }

    public ASN1SetParser getRecipientInfos() throws IOException {
        if (!this.originatorInfoCalled) {
            this.getOriginatorInfo();
        }

        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }

        ASN1SetParser recipientInfos = (ASN1SetParser)this.nextObject;
        this.nextObject = null;
        return recipientInfos;
    }

    public AlgorithmIdentifier getMacAlgorithm() throws IOException {
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }

        if (this.nextObject != null) {
            ASN1SequenceParser o = (ASN1SequenceParser)this.nextObject;
            this.nextObject = null;
            return AlgorithmIdentifier.getInstance(o.toASN1Primitive());
        } else {
            return null;
        }
    }

    public AlgorithmIdentifier getDigestAlgorithm() throws IOException {
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }

        if (this.nextObject instanceof ASN1TaggedObjectParser) {
            AlgorithmIdentifier obj = AlgorithmIdentifier.getInstance((ASN1TaggedObject)this.nextObject.toASN1Primitive(), false);
            this.nextObject = null;
            return obj;
        } else {
            return null;
        }
    }

    public ContentInfoParser getEncapsulatedContentInfo() throws IOException {
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }

        if (this.nextObject != null) {
            ASN1SequenceParser o = (ASN1SequenceParser)this.nextObject;
            this.nextObject = null;
            return new ContentInfoParser(o);
        } else {
            return null;
        }
    }

    public ASN1SetParser getAuthAttrs() throws IOException {
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }

        if (this.nextObject instanceof ASN1TaggedObjectParser) {
            ASN1TaggedObjectParser o = (ASN1TaggedObjectParser)this.nextObject;
            this.nextObject = null;
            return (ASN1SetParser)ASN1Util.parseContextBaseUniversal(o, 2, false, 17);
        } else {
            return null;
        }
    }

    public ASN1OctetString getMac() throws IOException {
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }

        ASN1Encodable o = this.nextObject;
        this.nextObject = null;
        return ASN1OctetString.getInstance(o.toASN1Primitive());
    }

    public ASN1SetParser getUnauthAttrs() throws IOException {
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }

        if (this.nextObject != null) {
            ASN1TaggedObject o = (ASN1TaggedObject)this.nextObject;
            this.nextObject = null;
            return (ASN1SetParser)ASN1Util.parseContextBaseUniversal(o, 3, false, 17);
        } else {
            return null;
        }
    }
}