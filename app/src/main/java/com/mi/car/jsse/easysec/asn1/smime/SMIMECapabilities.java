package com.mi.car.jsse.easysec.asn1.smime;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.cms.Attribute;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import java.util.Enumeration;
import java.util.Vector;

public class SMIMECapabilities extends ASN1Object {
    public static final ASN1ObjectIdentifier preferSignedData;
    public static final ASN1ObjectIdentifier canNotDecryptAny;
    public static final ASN1ObjectIdentifier sMIMECapabilitesVersions;
    public static final ASN1ObjectIdentifier aes256_CBC;
    public static final ASN1ObjectIdentifier aes192_CBC;
    public static final ASN1ObjectIdentifier aes128_CBC;
    public static final ASN1ObjectIdentifier idea_CBC;
    public static final ASN1ObjectIdentifier cast5_CBC;
    public static final ASN1ObjectIdentifier dES_CBC;
    public static final ASN1ObjectIdentifier dES_EDE3_CBC;
    public static final ASN1ObjectIdentifier rC2_CBC;
    private ASN1Sequence capabilities;

    public static SMIMECapabilities getInstance(Object o) {
        if (o != null && !(o instanceof SMIMECapabilities)) {
            if (o instanceof ASN1Sequence) {
                return new SMIMECapabilities((ASN1Sequence)o);
            } else if (o instanceof Attribute) {
                return new SMIMECapabilities((ASN1Sequence)((ASN1Sequence)((Attribute)o).getAttrValues().getObjectAt(0)));
            } else {
                throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
            }
        } else {
            return (SMIMECapabilities)o;
        }
    }

    public SMIMECapabilities(ASN1Sequence seq) {
        this.capabilities = seq;
    }

    public Vector getCapabilities(ASN1ObjectIdentifier capability) {
        Enumeration e = this.capabilities.getObjects();
        Vector list = new Vector();
        SMIMECapability cap;
        if (capability == null) {
            while(e.hasMoreElements()) {
                cap = SMIMECapability.getInstance(e.nextElement());
                list.addElement(cap);
            }
        } else {
            while(e.hasMoreElements()) {
                cap = SMIMECapability.getInstance(e.nextElement());
                if (capability.equals(cap.getCapabilityID())) {
                    list.addElement(cap);
                }
            }
        }

        return list;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.capabilities;
    }

    static {
        preferSignedData = PKCSObjectIdentifiers.preferSignedData;
        canNotDecryptAny = PKCSObjectIdentifiers.canNotDecryptAny;
        sMIMECapabilitesVersions = PKCSObjectIdentifiers.sMIMECapabilitiesVersions;
        aes256_CBC = NISTObjectIdentifiers.id_aes256_CBC;
        aes192_CBC = NISTObjectIdentifiers.id_aes192_CBC;
        aes128_CBC = NISTObjectIdentifiers.id_aes128_CBC;
        idea_CBC = new ASN1ObjectIdentifier("1.3.6.1.4.1.188.7.1.1.2");
        cast5_CBC = new ASN1ObjectIdentifier("1.2.840.113533.7.66.10");
        dES_CBC = new ASN1ObjectIdentifier("1.3.14.3.2.7");
        dES_EDE3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC;
        rC2_CBC = PKCSObjectIdentifiers.RC2_CBC;
    }
}
