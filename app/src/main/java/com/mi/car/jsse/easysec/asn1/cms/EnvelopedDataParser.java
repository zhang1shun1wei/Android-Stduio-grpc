//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1SequenceParser;
import com.mi.car.jsse.easysec.asn1.ASN1SetParser;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObjectParser;
import com.mi.car.jsse.easysec.asn1.ASN1Util;
import java.io.IOException;

public class EnvelopedDataParser {
    private ASN1SequenceParser _seq;
    private ASN1Integer _version;
    private ASN1Encodable _nextObject;
    private boolean _originatorInfoCalled;

    public EnvelopedDataParser(ASN1SequenceParser seq) throws IOException {
        this._seq = seq;
        this._version = ASN1Integer.getInstance(seq.readObject());
    }

    public ASN1Integer getVersion() {
        return this._version;
    }

    public OriginatorInfo getOriginatorInfo() throws IOException {
        this._originatorInfoCalled = true;
        if (this._nextObject == null) {
            this._nextObject = this._seq.readObject();
        }

        if (this._nextObject instanceof ASN1TaggedObjectParser) {
            ASN1TaggedObjectParser o = (ASN1TaggedObjectParser)this._nextObject;
            if (o.hasContextTag(0)) {
                ASN1SequenceParser originatorInfo = (ASN1SequenceParser)o.parseBaseUniversal(false, 16);
                this._nextObject = null;
                return OriginatorInfo.getInstance(originatorInfo.getLoadedObject());
            }
        }

        return null;
    }

    public ASN1SetParser getRecipientInfos() throws IOException {
        if (!this._originatorInfoCalled) {
            this.getOriginatorInfo();
        }

        if (this._nextObject == null) {
            this._nextObject = this._seq.readObject();
        }

        ASN1SetParser recipientInfos = (ASN1SetParser)this._nextObject;
        this._nextObject = null;
        return recipientInfos;
    }

    public EncryptedContentInfoParser getEncryptedContentInfo() throws IOException {
        if (this._nextObject == null) {
            this._nextObject = this._seq.readObject();
        }

        if (this._nextObject != null) {
            ASN1SequenceParser o = (ASN1SequenceParser)this._nextObject;
            this._nextObject = null;
            return new EncryptedContentInfoParser(o);
        } else {
            return null;
        }
    }

    public ASN1SetParser getUnprotectedAttrs() throws IOException {
        if (this._nextObject == null) {
            this._nextObject = this._seq.readObject();
        }

        if (this._nextObject != null) {
            ASN1TaggedObjectParser o = (ASN1TaggedObjectParser)this._nextObject;
            this._nextObject = null;
            return (ASN1SetParser)ASN1Util.parseContextBaseUniversal(o, 1, false, 17);
        } else {
            return null;
        }
    }
}
