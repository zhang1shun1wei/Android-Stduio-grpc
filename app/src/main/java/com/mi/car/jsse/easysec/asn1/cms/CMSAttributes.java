//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;

public interface CMSAttributes {
    ASN1ObjectIdentifier contentType = PKCSObjectIdentifiers.pkcs_9_at_contentType;
    ASN1ObjectIdentifier messageDigest = PKCSObjectIdentifiers.pkcs_9_at_messageDigest;
    ASN1ObjectIdentifier signingTime = PKCSObjectIdentifiers.pkcs_9_at_signingTime;
    ASN1ObjectIdentifier counterSignature = PKCSObjectIdentifiers.pkcs_9_at_counterSignature;
    ASN1ObjectIdentifier binarySigningTime = PKCSObjectIdentifiers.pkcs_9_at_binarySigningTime;
    ASN1ObjectIdentifier contentHint = PKCSObjectIdentifiers.id_aa_contentHint;
    ASN1ObjectIdentifier cmsAlgorithmProtect = PKCSObjectIdentifiers.id_aa_cmsAlgorithmProtect;
}
