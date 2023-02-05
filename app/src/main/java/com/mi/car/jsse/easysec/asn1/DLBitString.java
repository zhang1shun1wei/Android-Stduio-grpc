package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class DLBitString extends ASN1BitString {
    public DLBitString(byte[] data) {
        this(data, 0);
    }

    public DLBitString(byte data, int padBits) {
        super(data, padBits);
    }

    public DLBitString(byte[] data, int padBits) {
        super(data, padBits);
    }

    public DLBitString(int value) {
        super(getBytes(value), getPadBits(value));
    }

    public DLBitString(ASN1Encodable obj) throws IOException {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    DLBitString(byte[] contents, boolean check) {
        super(contents, check);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return false;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, this.contents.length);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingDL(withTag, 3, this.contents);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitString, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }

    static int encodedLength(boolean withTag, int contentsLength) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contentsLength);
    }

    static void encode(ASN1OutputStream out, boolean withTag, byte[] buf, int off, int len) throws IOException {
        out.writeEncodingDL(withTag, 3, buf, off, len);
    }

    static void encode(ASN1OutputStream out, boolean withTag, byte pad, byte[] buf, int off, int len) throws IOException {
        out.writeEncodingDL(withTag, 3, pad, buf, off, len);
    }
}
