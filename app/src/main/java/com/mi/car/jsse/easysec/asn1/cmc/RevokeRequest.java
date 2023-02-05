//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERUTF8String;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x509.CRLReason;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class RevokeRequest extends ASN1Object {
    private final X500Name name;
    private final ASN1Integer serialNumber;
    private final CRLReason reason;
    private ASN1GeneralizedTime invalidityDate;
    private ASN1OctetString passphrase;
    private ASN1UTF8String comment;

    public RevokeRequest(X500Name name, ASN1Integer serialNumber, CRLReason reason, ASN1GeneralizedTime invalidityDate, ASN1OctetString passphrase, ASN1UTF8String comment) {
        this.name = name;
        this.serialNumber = serialNumber;
        this.reason = reason;
        this.invalidityDate = invalidityDate;
        this.passphrase = passphrase;
        this.comment = comment;
    }

    private RevokeRequest(ASN1Sequence seq) {
        if (seq.size() >= 3 && seq.size() <= 6) {
            this.name = X500Name.getInstance(seq.getObjectAt(0));
            this.serialNumber = ASN1Integer.getInstance(seq.getObjectAt(1));
            this.reason = CRLReason.getInstance(seq.getObjectAt(2));
            int index = 3;
            if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() instanceof ASN1GeneralizedTime) {
                this.invalidityDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(index++));
            }

            if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() instanceof ASN1OctetString) {
                this.passphrase = ASN1OctetString.getInstance(seq.getObjectAt(index++));
            }

            if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() instanceof ASN1UTF8String) {
                this.comment = ASN1UTF8String.getInstance(seq.getObjectAt(index));
            }

        } else {
            throw new IllegalArgumentException("incorrect sequence size");
        }
    }

    public static RevokeRequest getInstance(Object o) {
        if (o instanceof RevokeRequest) {
            return (RevokeRequest)o;
        } else {
            return o != null ? new RevokeRequest(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public X500Name getName() {
        return this.name;
    }

    public BigInteger getSerialNumber() {
        return this.serialNumber.getValue();
    }

    public CRLReason getReason() {
        return this.reason;
    }

    public ASN1GeneralizedTime getInvalidityDate() {
        return this.invalidityDate;
    }

    public void setInvalidityDate(ASN1GeneralizedTime invalidityDate) {
        this.invalidityDate = invalidityDate;
    }

    public ASN1OctetString getPassphrase() {
        return this.passphrase;
    }

    public void setPassphrase(ASN1OctetString passphrase) {
        this.passphrase = passphrase;
    }

    /** @deprecated */
    public DERUTF8String getComment() {
        return null != this.comment && !(this.comment instanceof DERUTF8String) ? new DERUTF8String(this.comment.getString()) : (DERUTF8String)this.comment;
    }

    public ASN1UTF8String getCommentUTF8() {
        return this.comment;
    }

    public void setComment(ASN1UTF8String comment) {
        this.comment = comment;
    }

    public byte[] getPassPhrase() {
        return this.passphrase != null ? Arrays.clone(this.passphrase.getOctets()) : null;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(6);
        v.add(this.name);
        v.add(this.serialNumber);
        v.add(this.reason);
        if (this.invalidityDate != null) {
            v.add(this.invalidityDate);
        }

        if (this.passphrase != null) {
            v.add(this.passphrase);
        }

        if (this.comment != null) {
            v.add(this.comment);
        }

        return new DERSequence(v);
    }
}