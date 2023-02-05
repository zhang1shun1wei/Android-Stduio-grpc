package com.mi.car.jsse.easysec.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class DERSequenceGenerator extends DERGenerator {
    private final ByteArrayOutputStream _bOut = new ByteArrayOutputStream();

    public DERSequenceGenerator(OutputStream out) throws IOException {
        super(out);
    }

    public DERSequenceGenerator(OutputStream out, int tagNo, boolean isExplicit) throws IOException {
        super(out, tagNo, isExplicit);
    }

    public void addObject(ASN1Encodable object) throws IOException {
        object.toASN1Primitive().encodeTo(this._bOut, ASN1Encoding.DER);
    }

    public void addObject(ASN1Primitive primitive) throws IOException {
        primitive.encodeTo(this._bOut, ASN1Encoding.DER);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Generator
    public OutputStream getRawOutputStream() {
        return this._bOut;
    }

    public void close() throws IOException {
        writeDEREncoded(48, this._bOut.toByteArray());
    }
}
