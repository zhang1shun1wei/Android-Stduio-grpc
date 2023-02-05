package com.mi.car.jsse.easysec.asn1.ocsp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;
import com.mi.car.jsse.easysec.asn1.x509.X509Extensions;

public class ResponseData extends ASN1Object {
    private static final ASN1Integer V1 = new ASN1Integer(0);
    private ASN1GeneralizedTime producedAt;
    private ResponderID responderID;
    private Extensions responseExtensions;
    private ASN1Sequence responses;
    private ASN1Integer version;
    private boolean versionPresent;

    public ResponseData(ASN1Integer version2, ResponderID responderID2, ASN1GeneralizedTime producedAt2, ASN1Sequence responses2, Extensions responseExtensions2) {
        this.version = version2;
        this.responderID = responderID2;
        this.producedAt = producedAt2;
        this.responses = responses2;
        this.responseExtensions = responseExtensions2;
    }

    public ResponseData(ResponderID responderID2, ASN1GeneralizedTime producedAt2, ASN1Sequence responses2, X509Extensions responseExtensions2) {
        this(V1, responderID2, ASN1GeneralizedTime.getInstance(producedAt2), responses2, Extensions.getInstance(responseExtensions2));
    }

    public ResponseData(ResponderID responderID2, ASN1GeneralizedTime producedAt2, ASN1Sequence responses2, Extensions responseExtensions2) {
        this(V1, responderID2, producedAt2, responses2, responseExtensions2);
    }

    private ResponseData(ASN1Sequence seq) {
        int index = 0;
        if (!(seq.getObjectAt(0) instanceof ASN1TaggedObject)) {
            this.version = V1;
        } else if (((ASN1TaggedObject) seq.getObjectAt(0)).getTagNo() == 0) {
            this.versionPresent = true;
            this.version = ASN1Integer.getInstance((ASN1TaggedObject) seq.getObjectAt(0), true);
            index = 0 + 1;
        } else {
            this.version = V1;
        }
        int index2 = index + 1;
        this.responderID = ResponderID.getInstance(seq.getObjectAt(index));
        int index3 = index2 + 1;
        this.producedAt = ASN1GeneralizedTime.getInstance(seq.getObjectAt(index2));
        int index4 = index3 + 1;
        this.responses = (ASN1Sequence) seq.getObjectAt(index3);
        if (seq.size() > index4) {
            this.responseExtensions = Extensions.getInstance((ASN1TaggedObject) seq.getObjectAt(index4), true);
        }
    }

    public static ResponseData getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ResponseData getInstance(Object obj) {
        if (obj instanceof ResponseData) {
            return (ResponseData) obj;
        }
        if (obj != null) {
            return new ResponseData(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public ResponderID getResponderID() {
        return this.responderID;
    }

    public ASN1GeneralizedTime getProducedAt() {
        return this.producedAt;
    }

    public ASN1Sequence getResponses() {
        return this.responses;
    }

    public Extensions getResponseExtensions() {
        return this.responseExtensions;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(5);
        if (this.versionPresent || !this.version.equals((ASN1Primitive) V1)) {
            v.add(new DERTaggedObject(true, 0, (ASN1Encodable) this.version));
        }
        v.add(this.responderID);
        v.add(this.producedAt);
        v.add(this.responses);
        if (this.responseExtensions != null) {
            v.add(new DERTaggedObject(true, 1, (ASN1Encodable) this.responseExtensions));
        }
        return new DERSequence(v);
    }
}
