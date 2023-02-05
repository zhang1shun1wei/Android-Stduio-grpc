package com.mi.car.jsse.easysec.tls.crypto;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import java.io.IOException;
import java.math.BigInteger;

public interface TlsCertificate {
    TlsCertificate checkUsageInRole(int i) throws IOException;

    TlsEncryptor createEncryptor(int i) throws IOException;

    TlsVerifier createVerifier(int i) throws IOException;

    TlsVerifier createVerifier(short s) throws IOException;

    byte[] getEncoded() throws IOException;

    byte[] getExtension(ASN1ObjectIdentifier aSN1ObjectIdentifier) throws IOException;

    short getLegacySignatureAlgorithm() throws IOException;

    BigInteger getSerialNumber();

    String getSigAlgOID();

    ASN1Encodable getSigAlgParams() throws IOException;

    boolean supportsSignatureAlgorithm(short s) throws IOException;

    boolean supportsSignatureAlgorithmCA(short s) throws IOException;
}
