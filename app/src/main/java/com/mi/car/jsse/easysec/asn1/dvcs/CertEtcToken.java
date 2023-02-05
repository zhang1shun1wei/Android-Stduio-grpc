package com.mi.car.jsse.easysec.asn1.dvcs;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.cmp.PKIStatusInfo;
import com.mi.car.jsse.easysec.asn1.cms.ContentInfo;
import com.mi.car.jsse.easysec.asn1.ess.ESSCertID;
import com.mi.car.jsse.easysec.asn1.ocsp.CertID;
import com.mi.car.jsse.easysec.asn1.ocsp.CertStatus;
import com.mi.car.jsse.easysec.asn1.ocsp.OCSPResponse;
import com.mi.car.jsse.easysec.asn1.smime.SMIMECapabilities;
import com.mi.car.jsse.easysec.asn1.x509.Certificate;
import com.mi.car.jsse.easysec.asn1.x509.CertificateList;
import com.mi.car.jsse.easysec.asn1.x509.Extension;

public class CertEtcToken extends ASN1Object implements ASN1Choice {
    public static final int TAG_ASSERTION = 3;
    public static final int TAG_CAPABILITIES = 8;
    public static final int TAG_CERTIFICATE = 0;
    public static final int TAG_CRL = 4;
    public static final int TAG_ESSCERTID = 1;
    public static final int TAG_OCSPCERTID = 6;
    public static final int TAG_OCSPCERTSTATUS = 5;
    public static final int TAG_OCSPRESPONSE = 7;
    public static final int TAG_PKISTATUS = 2;
    private static final boolean[] explicit = {false, true, false, true, false, true, false, false, true};
    private Extension extension;
    private int tagNo;
    private ASN1Encodable value;

    public CertEtcToken(int tagNo2, ASN1Encodable value2) {
        this.tagNo = tagNo2;
        this.value = value2;
    }

    public CertEtcToken(Extension extension2) {
        this.tagNo = -1;
        this.extension = extension2;
    }

    private CertEtcToken(ASN1TaggedObject choice) {
        this.tagNo = choice.getTagNo();
        switch (this.tagNo) {
            case 0:
                this.value = Certificate.getInstance(choice, false);
                return;
            case 1:
                this.value = ESSCertID.getInstance(choice.getObject());
                return;
            case 2:
                this.value = PKIStatusInfo.getInstance(choice, false);
                return;
            case 3:
                this.value = ContentInfo.getInstance(choice.getObject());
                return;
            case 4:
                this.value = CertificateList.getInstance(choice, false);
                return;
            case 5:
                this.value = CertStatus.getInstance(choice.getObject());
                return;
            case 6:
                this.value = CertID.getInstance(choice, false);
                return;
            case 7:
                this.value = OCSPResponse.getInstance(choice, false);
                return;
            case 8:
                this.value = SMIMECapabilities.getInstance(choice.getObject());
                return;
            default:
                throw new IllegalArgumentException("Unknown tag: " + this.tagNo);
        }
    }

    public static CertEtcToken getInstance(Object obj) {
        if (obj instanceof CertEtcToken) {
            return (CertEtcToken) obj;
        }
        if (obj instanceof ASN1TaggedObject) {
            return new CertEtcToken((ASN1TaggedObject) obj);
        }
        if (obj != null) {
            return new CertEtcToken(Extension.getInstance(obj));
        }
        return null;
    }

    public ASN1Primitive toASN1Primitive() {
        if (this.extension == null) {
            return new DERTaggedObject(explicit[this.tagNo], this.tagNo, this.value);
        }
        return this.extension.toASN1Primitive();
    }

    public int getTagNo() {
        return this.tagNo;
    }

    public ASN1Encodable getValue() {
        return this.value;
    }

    public Extension getExtension() {
        return this.extension;
    }

    public String toString() {
        return "CertEtcToken {\n" + this.value + "}\n";
    }

    public static CertEtcToken[] arrayFromSequence(ASN1Sequence seq) {
        CertEtcToken[] tmp = new CertEtcToken[seq.size()];
        for (int i = 0; i != tmp.length; i++) {
            tmp[i] = getInstance(seq.getObjectAt(i));
        }
        return tmp;
    }
}
