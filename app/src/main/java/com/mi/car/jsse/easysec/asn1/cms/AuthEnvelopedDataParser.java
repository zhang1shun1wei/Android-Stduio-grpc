//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1ParsingException;
import com.mi.car.jsse.easysec.asn1.ASN1SequenceParser;
import com.mi.car.jsse.easysec.asn1.ASN1SetParser;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser;
import com.mi.car.jsse.easysec.asn1.ASN1Util;
import java.io.IOException;

public class AuthEnvelopedDataParser {
    private ASN1SequenceParser seq;
    private ASN1Integer version;
    private ASN1Encodable nextObject;
    private boolean originatorInfoCalled;
    private boolean isData;

    public AuthEnvelopedDataParser(ASN1SequenceParser seq) throws IOException {
        this.seq = seq;
        this.version = ASN1Integer.getInstance(seq.readObject());
        if (!this.version.hasValue(0)) {
            throw new ASN1ParsingException("AuthEnvelopedData version number must be 0");
        }
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

    public EncryptedContentInfoParser getAuthEncryptedContentInfo() throws IOException {
        if (this.nextObject == null) {
            this.nextObject = this.seq.readObject();
        }

        if (this.nextObject != null) {
            ASN1SequenceParser o = (ASN1SequenceParser)this.nextObject;
            this.nextObject = null;
            EncryptedContentInfoParser encryptedContentInfoParser = new EncryptedContentInfoParser(o);
            this.isData = CMSObjectIdentifiers.data.equals(encryptedContentInfoParser.getContentType());
            return encryptedContentInfoParser;
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
            return (ASN1SetParser)ASN1Util.parseContextBaseUniversal(o, 1, false, 17);
        } else if (!this.isData) {
            throw new ASN1ParsingException("authAttrs must be present with non-data content");
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
            ASN1TaggedObjectParser o = (ASN1TaggedObjectParser)this.nextObject;
            this.nextObject = null;
            return (ASN1SetParser)ASN1Util.parseContextBaseUniversal(o, 2, false, 17);
        } else {
            return null;
        }
    }
}

