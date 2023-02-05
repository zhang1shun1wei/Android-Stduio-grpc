package com.mi.car.jsse.easysec.asn1.eac;

import java.io.UnsupportedEncodingException;

public class CertificateHolderReference {
    private static final String ReferenceEncoding = "ISO-8859-1";
    private String countryCode;
    private String holderMnemonic;
    private String sequenceNumber;

    public CertificateHolderReference(String countryCode2, String holderMnemonic2, String sequenceNumber2) {
        this.countryCode = countryCode2;
        this.holderMnemonic = holderMnemonic2;
        this.sequenceNumber = sequenceNumber2;
    }

    CertificateHolderReference(byte[] contents) {
        try {
            String concat = new String(contents, ReferenceEncoding);
            this.countryCode = concat.substring(0, 2);
            this.holderMnemonic = concat.substring(2, concat.length() - 5);
            this.sequenceNumber = concat.substring(concat.length() - 5);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e.toString());
        }
    }

    public String getCountryCode() {
        return this.countryCode;
    }

    public String getHolderMnemonic() {
        return this.holderMnemonic;
    }

    public String getSequenceNumber() {
        return this.sequenceNumber;
    }

    public byte[] getEncoded() {
        try {
            return (this.countryCode + this.holderMnemonic + this.sequenceNumber).getBytes(ReferenceEncoding);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e.toString());
        }
    }
}
