package com.mi.car.jsse.easysec.asn1.dvcs;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.DigestInfo;

public class Data extends ASN1Object implements ASN1Choice {
    private ASN1Sequence certs;
    private ASN1OctetString message;
    private DigestInfo messageImprint;

    public Data(byte[] messageBytes) {
        this.message = new DEROctetString(messageBytes);
    }

    public Data(ASN1OctetString message2) {
        this.message = message2;
    }

    public Data(DigestInfo messageImprint2) {
        this.messageImprint = messageImprint2;
    }

    public Data(TargetEtcChain cert) {
        this.certs = new DERSequence(cert);
    }

    public Data(TargetEtcChain[] certs2) {
        this.certs = new DERSequence(certs2);
    }

    private Data(ASN1Sequence certs2) {
        this.certs = certs2;
    }

    public static Data getInstance(Object obj) {
        if (obj instanceof Data) {
            return (Data) obj;
        }
        if (obj instanceof ASN1OctetString) {
            return new Data((ASN1OctetString) obj);
        }
        if (obj instanceof ASN1Sequence) {
            return new Data(DigestInfo.getInstance(obj));
        }
        if (obj instanceof ASN1TaggedObject) {
            return new Data(ASN1Sequence.getInstance((ASN1TaggedObject) obj, false));
        }
        throw new IllegalArgumentException("Unknown object submitted to getInstance: " + obj.getClass().getName());
    }

    public static Data getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(obj.getObject());
    }

    public ASN1Primitive toASN1Primitive() {
        if (this.message != null) {
            return this.message.toASN1Primitive();
        }
        if (this.messageImprint != null) {
            return this.messageImprint.toASN1Primitive();
        }
        return new DERTaggedObject(false, 0, this.certs);
    }

    public String toString() {
        if (this.message != null) {
            return "Data {\n" + this.message + "}\n";
        }
        if (this.messageImprint != null) {
            return "Data {\n" + this.messageImprint + "}\n";
        }
        return "Data {\n" + this.certs + "}\n";
    }

    public ASN1OctetString getMessage() {
        return this.message;
    }

    public DigestInfo getMessageImprint() {
        return this.messageImprint;
    }

    public TargetEtcChain[] getCerts() {
        if (this.certs == null) {
            return null;
        }
        TargetEtcChain[] tmp = new TargetEtcChain[this.certs.size()];
        for (int i = 0; i != tmp.length; i++) {
            tmp[i] = TargetEtcChain.getInstance(this.certs.getObjectAt(i));
        }
        return tmp;
    }
}
