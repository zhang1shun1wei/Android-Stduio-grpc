package com.mi.car.jsse.easysec.asn1.smime;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;

public interface SMIMEAttributes {
    public static final ASN1ObjectIdentifier encrypKeyPref = PKCSObjectIdentifiers.id_aa_encrypKeyPref;
    public static final ASN1ObjectIdentifier smimeCapabilities = PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities;
}
