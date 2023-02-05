package com.mi.car.jsse.easysec.asn1.smime;

import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.DERSet;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.cms.Attribute;
import com.mi.car.jsse.easysec.asn1.cms.IssuerAndSerialNumber;
import com.mi.car.jsse.easysec.asn1.cms.RecipientKeyIdentifier;

public class SMIMEEncryptionKeyPreferenceAttribute extends Attribute {
    public SMIMEEncryptionKeyPreferenceAttribute(IssuerAndSerialNumber issAndSer) {
        super(SMIMEAttributes.encrypKeyPref, new DERSet(new DERTaggedObject(false, 0, issAndSer)));
    }

    public SMIMEEncryptionKeyPreferenceAttribute(RecipientKeyIdentifier rKeyId) {
        super(SMIMEAttributes.encrypKeyPref, new DERSet(new DERTaggedObject(false, 1, rKeyId)));
    }

    public SMIMEEncryptionKeyPreferenceAttribute(ASN1OctetString sKeyId) {
        super(SMIMEAttributes.encrypKeyPref, new DERSet(new DERTaggedObject(false, 2, sKeyId)));
    }
}
