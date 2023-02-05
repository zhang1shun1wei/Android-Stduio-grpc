package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.X509ObjectIdentifiers;

public interface TlsObjectIdentifiers {
    public static final ASN1ObjectIdentifier id_pe_tlsfeature = X509ObjectIdentifiers.id_pe.branch("24");
}
