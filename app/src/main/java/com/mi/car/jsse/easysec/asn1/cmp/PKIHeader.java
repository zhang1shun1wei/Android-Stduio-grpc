//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import java.util.Enumeration;

public class PKIHeader extends ASN1Object {
    public static final GeneralName NULL_NAME = new GeneralName(X500Name.getInstance(new DERSequence()));
    public static final int CMP_1999 = 1;
    public static final int CMP_2000 = 2;
    public static final int CMP_2021 = 3;
    private final ASN1Integer pvno;
    private final GeneralName sender;
    private final GeneralName recipient;
    private ASN1GeneralizedTime messageTime;
    private AlgorithmIdentifier protectionAlg;
    private ASN1OctetString senderKID;
    private ASN1OctetString recipKID;
    private ASN1OctetString transactionID;
    private ASN1OctetString senderNonce;
    private ASN1OctetString recipNonce;
    private PKIFreeText freeText;
    private ASN1Sequence generalInfo;

    private PKIHeader(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        this.pvno = ASN1Integer.getInstance(en.nextElement());
        this.sender = GeneralName.getInstance(en.nextElement());
        this.recipient = GeneralName.getInstance(en.nextElement());

        while(en.hasMoreElements()) {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();
            switch(tObj.getTagNo()) {
                case 0:
                    this.messageTime = ASN1GeneralizedTime.getInstance(tObj, true);
                    break;
                case 1:
                    this.protectionAlg = AlgorithmIdentifier.getInstance(tObj, true);
                    break;
                case 2:
                    this.senderKID = ASN1OctetString.getInstance(tObj, true);
                    break;
                case 3:
                    this.recipKID = ASN1OctetString.getInstance(tObj, true);
                    break;
                case 4:
                    this.transactionID = ASN1OctetString.getInstance(tObj, true);
                    break;
                case 5:
                    this.senderNonce = ASN1OctetString.getInstance(tObj, true);
                    break;
                case 6:
                    this.recipNonce = ASN1OctetString.getInstance(tObj, true);
                    break;
                case 7:
                    this.freeText = PKIFreeText.getInstance(tObj, true);
                    break;
                case 8:
                    this.generalInfo = ASN1Sequence.getInstance(tObj, true);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }

    }

    public PKIHeader(int pvno, GeneralName sender, GeneralName recipient) {
        this(new ASN1Integer((long)pvno), sender, recipient);
    }

    private PKIHeader(ASN1Integer pvno, GeneralName sender, GeneralName recipient) {
        this.pvno = pvno;
        this.sender = sender;
        this.recipient = recipient;
    }

    public static PKIHeader getInstance(Object o) {
        if (o instanceof PKIHeader) {
            return (PKIHeader)o;
        } else {
            return o != null ? new PKIHeader(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ASN1Integer getPvno() {
        return this.pvno;
    }

    public GeneralName getSender() {
        return this.sender;
    }

    public GeneralName getRecipient() {
        return this.recipient;
    }

    public ASN1GeneralizedTime getMessageTime() {
        return this.messageTime;
    }

    public AlgorithmIdentifier getProtectionAlg() {
        return this.protectionAlg;
    }

    public ASN1OctetString getSenderKID() {
        return this.senderKID;
    }

    public ASN1OctetString getRecipKID() {
        return this.recipKID;
    }

    public ASN1OctetString getTransactionID() {
        return this.transactionID;
    }

    public ASN1OctetString getSenderNonce() {
        return this.senderNonce;
    }

    public ASN1OctetString getRecipNonce() {
        return this.recipNonce;
    }

    public PKIFreeText getFreeText() {
        return this.freeText;
    }

    public InfoTypeAndValue[] getGeneralInfo() {
        if (this.generalInfo == null) {
            return null;
        } else {
            InfoTypeAndValue[] results = new InfoTypeAndValue[this.generalInfo.size()];

            for(int i = 0; i < results.length; ++i) {
                results[i] = InfoTypeAndValue.getInstance(this.generalInfo.getObjectAt(i));
            }

            return results;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(12);
        v.add(this.pvno);
        v.add(this.sender);
        v.add(this.recipient);
        this.addOptional(v, 0, this.messageTime);
        this.addOptional(v, 1, this.protectionAlg);
        this.addOptional(v, 2, this.senderKID);
        this.addOptional(v, 3, this.recipKID);
        this.addOptional(v, 4, this.transactionID);
        this.addOptional(v, 5, this.senderNonce);
        this.addOptional(v, 6, this.recipNonce);
        this.addOptional(v, 7, this.freeText);
        this.addOptional(v, 8, this.generalInfo);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }

    }
}
