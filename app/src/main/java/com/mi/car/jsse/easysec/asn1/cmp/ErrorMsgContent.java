//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;

public class ErrorMsgContent extends ASN1Object {
    private final PKIStatusInfo pkiStatusInfo;
    private ASN1Integer errorCode;
    private PKIFreeText errorDetails;

    private ErrorMsgContent(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        this.pkiStatusInfo = PKIStatusInfo.getInstance(en.nextElement());

        while(en.hasMoreElements()) {
            Object o = en.nextElement();
            if (o instanceof ASN1Integer) {
                this.errorCode = ASN1Integer.getInstance(o);
            } else {
                this.errorDetails = PKIFreeText.getInstance(o);
            }
        }

    }

    public ErrorMsgContent(PKIStatusInfo pkiStatusInfo) {
        this(pkiStatusInfo, (ASN1Integer)null, (PKIFreeText)null);
    }

    public ErrorMsgContent(PKIStatusInfo pkiStatusInfo, ASN1Integer errorCode, PKIFreeText errorDetails) {
        if (pkiStatusInfo == null) {
            throw new IllegalArgumentException("'pkiStatusInfo' cannot be null");
        } else {
            this.pkiStatusInfo = pkiStatusInfo;
            this.errorCode = errorCode;
            this.errorDetails = errorDetails;
        }
    }

    public static ErrorMsgContent getInstance(Object o) {
        if (o instanceof ErrorMsgContent) {
            return (ErrorMsgContent)o;
        } else {
            return o != null ? new ErrorMsgContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public PKIStatusInfo getPKIStatusInfo() {
        return this.pkiStatusInfo;
    }

    public ASN1Integer getErrorCode() {
        return this.errorCode;
    }

    public PKIFreeText getErrorDetails() {
        return this.errorDetails;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.pkiStatusInfo);
        this.addOptional(v, this.errorCode);
        this.addOptional(v, this.errorDetails);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, ASN1Encodable obj) {
        if (obj != null) {
            v.add(obj);
        }

    }
}
