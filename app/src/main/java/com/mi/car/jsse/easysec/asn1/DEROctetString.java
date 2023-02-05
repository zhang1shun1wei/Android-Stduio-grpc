package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class DEROctetString extends ASN1OctetString {
    public DEROctetString(byte[] string) {
        super(string);
    }

    public DEROctetString(ASN1Encodable obj) throws IOException {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return false;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, this.string.length);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingDL(withTag, 4, this.string);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive, com.mi.car.jsse.easysec.asn1.ASN1OctetString
    public ASN1Primitive toDERObject() {
        return this;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive, com.mi.car.jsse.easysec.asn1.ASN1OctetString
    public ASN1Primitive toDLObject() {
        return this;
    }

    static void encode(ASN1OutputStream out, boolean withTag, byte[] buf, int off, int len) throws IOException {
        out.writeEncodingDL(withTag, 4, buf, off, len);
    }

    static int encodedLength(boolean withTag, int contentsLength) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contentsLength);
    }
}
