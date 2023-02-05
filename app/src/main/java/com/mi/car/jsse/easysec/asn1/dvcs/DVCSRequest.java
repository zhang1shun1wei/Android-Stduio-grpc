package com.mi.car.jsse.easysec.asn1.dvcs;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;

public class DVCSRequest extends ASN1Object {
    private Data data;
    private DVCSRequestInformation requestInformation;
    private GeneralName transactionIdentifier;

    public DVCSRequest(DVCSRequestInformation requestInformation2, Data data2) {
        this(requestInformation2, data2, null);
    }

    public DVCSRequest(DVCSRequestInformation requestInformation2, Data data2, GeneralName transactionIdentifier2) {
        this.requestInformation = requestInformation2;
        this.data = data2;
        this.transactionIdentifier = transactionIdentifier2;
    }

    private DVCSRequest(ASN1Sequence seq) {
        this.requestInformation = DVCSRequestInformation.getInstance(seq.getObjectAt(0));
        this.data = Data.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2) {
            this.transactionIdentifier = GeneralName.getInstance(seq.getObjectAt(2));
        }
    }

    public static DVCSRequest getInstance(Object obj) {
        if (obj instanceof DVCSRequest) {
            return (DVCSRequest) obj;
        }
        if (obj != null) {
            return new DVCSRequest(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static DVCSRequest getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.requestInformation);
        v.add(this.data);
        if (this.transactionIdentifier != null) {
            v.add(this.transactionIdentifier);
        }
        return new DERSequence(v);
    }

    public String toString() {
        return "DVCSRequest {\nrequestInformation: " + this.requestInformation + "\ndata: " + this.data + "\n" + (this.transactionIdentifier != null ? "transactionIdentifier: " + this.transactionIdentifier + "\n" : "") + "}\n";
    }

    public Data getData() {
        return this.data;
    }

    public DVCSRequestInformation getRequestInformation() {
        return this.requestInformation;
    }

    public GeneralName getTransactionIdentifier() {
        return this.transactionIdentifier;
    }
}
