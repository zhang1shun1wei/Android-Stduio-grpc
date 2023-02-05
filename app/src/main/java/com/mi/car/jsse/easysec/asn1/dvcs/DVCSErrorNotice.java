package com.mi.car.jsse.easysec.asn1.dvcs;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.cmp.PKIStatusInfo;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;

public class DVCSErrorNotice extends ASN1Object {
    private GeneralName transactionIdentifier;
    private PKIStatusInfo transactionStatus;

    public DVCSErrorNotice(PKIStatusInfo status) {
        this(status, null);
    }

    public DVCSErrorNotice(PKIStatusInfo status, GeneralName transactionIdentifier2) {
        this.transactionStatus = status;
        this.transactionIdentifier = transactionIdentifier2;
    }

    private DVCSErrorNotice(ASN1Sequence seq) {
        this.transactionStatus = PKIStatusInfo.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.transactionIdentifier = GeneralName.getInstance(seq.getObjectAt(1));
        }
    }

    public static DVCSErrorNotice getInstance(Object obj) {
        if (obj instanceof DVCSErrorNotice) {
            return (DVCSErrorNotice) obj;
        }
        if (obj != null) {
            return new DVCSErrorNotice(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static DVCSErrorNotice getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.transactionStatus);
        if (this.transactionIdentifier != null) {
            v.add(this.transactionIdentifier);
        }
        return new DERSequence(v);
    }

    public String toString() {
        return "DVCSErrorNotice {\ntransactionStatus: " + this.transactionStatus + "\n" + (this.transactionIdentifier != null ? "transactionIdentifier: " + this.transactionIdentifier + "\n" : "") + "}\n";
    }

    public PKIStatusInfo getTransactionStatus() {
        return this.transactionStatus;
    }

    public GeneralName getTransactionIdentifier() {
        return this.transactionIdentifier;
    }
}
