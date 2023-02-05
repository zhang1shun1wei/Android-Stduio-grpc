package com.mi.car.jsse.easysec.asn1.smime;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;

public class SMIMECapability extends ASN1Object {
    public static final ASN1ObjectIdentifier preferSignedData;
    public static final ASN1ObjectIdentifier canNotDecryptAny;
    public static final ASN1ObjectIdentifier sMIMECapabilitiesVersions;
    public static final ASN1ObjectIdentifier dES_CBC;
    public static final ASN1ObjectIdentifier dES_EDE3_CBC;
    public static final ASN1ObjectIdentifier rC2_CBC;
    public static final ASN1ObjectIdentifier aES128_CBC;
    public static final ASN1ObjectIdentifier aES192_CBC;
    public static final ASN1ObjectIdentifier aES256_CBC;
    private ASN1ObjectIdentifier capabilityID;
    private ASN1Encodable parameters;

    public SMIMECapability(ASN1Sequence seq) {
        this.capabilityID = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        if (seq.size() > 1) {
            this.parameters = (ASN1Primitive)seq.getObjectAt(1);
        }

    }

    public SMIMECapability(ASN1ObjectIdentifier capabilityID, ASN1Encodable parameters) {
        this.capabilityID = capabilityID;
        this.parameters = parameters;
    }

    public static SMIMECapability getInstance(Object obj) {
        if (obj != null && !(obj instanceof SMIMECapability)) {
            if (obj instanceof ASN1Sequence) {
                return new SMIMECapability((ASN1Sequence)obj);
            } else {
                throw new IllegalArgumentException("Invalid SMIMECapability");
            }
        } else {
            return (SMIMECapability)obj;
        }
    }

    public ASN1ObjectIdentifier getCapabilityID() {
        return this.capabilityID;
    }

    public ASN1Encodable getParameters() {
        return this.parameters;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.capabilityID);
        if (this.parameters != null) {
            v.add(this.parameters);
        }

        return new DERSequence(v);
    }

    static {
        preferSignedData = PKCSObjectIdentifiers.preferSignedData;
        canNotDecryptAny = PKCSObjectIdentifiers.canNotDecryptAny;
        sMIMECapabilitiesVersions = PKCSObjectIdentifiers.sMIMECapabilitiesVersions;
        dES_CBC = new ASN1ObjectIdentifier("1.3.14.3.2.7");
        dES_EDE3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC;
        rC2_CBC = PKCSObjectIdentifiers.RC2_CBC;
        aES128_CBC = NISTObjectIdentifiers.id_aes128_CBC;
        aES192_CBC = NISTObjectIdentifiers.id_aes192_CBC;
        aES256_CBC = NISTObjectIdentifiers.id_aes256_CBC;
    }
}
