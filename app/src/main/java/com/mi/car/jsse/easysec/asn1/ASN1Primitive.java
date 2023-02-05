package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;
import java.io.OutputStream;

public abstract class ASN1Primitive extends ASN1Object {
    /* access modifiers changed from: package-private */
    public abstract boolean asn1Equals(ASN1Primitive aSN1Primitive);

    /* access modifiers changed from: package-private */
    public abstract void encode(ASN1OutputStream aSN1OutputStream, boolean z) throws IOException;

    /* access modifiers changed from: package-private */
    public abstract boolean encodeConstructed();

    /* access modifiers changed from: package-private */
    public abstract int encodedLength(boolean z) throws IOException;

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object
    public abstract int hashCode();

    ASN1Primitive() {
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object
    public void encodeTo(OutputStream output) throws IOException {
        ASN1OutputStream asn1Out = ASN1OutputStream.create(output);
        asn1Out.writePrimitive(this, true);
        asn1Out.flushInternal();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object
    public void encodeTo(OutputStream output, String encoding) throws IOException {
        ASN1OutputStream asn1Out = ASN1OutputStream.create(output, encoding);
        asn1Out.writePrimitive(this, true);
        asn1Out.flushInternal();
    }

    public static ASN1Primitive fromByteArray(byte[] data) throws IOException {
        ASN1InputStream aIn = new ASN1InputStream(data);
        try {
            ASN1Primitive o = aIn.readObject();
            if (aIn.available() == 0) {
                return o;
            }
            throw new IOException("Extra data detected in stream");
        } catch (ClassCastException e) {
            throw new IOException("cannot recognise object in stream");
        }
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ASN1Encodable) || !asn1Equals(((ASN1Encodable) o).toASN1Primitive())) {
            return false;
        }
        return true;
    }

    public final boolean equals(ASN1Encodable other) {
        return this == other || (other != null && asn1Equals(other.toASN1Primitive()));
    }

    public final boolean equals(ASN1Primitive other) {
        return this == other || asn1Equals(other);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public final ASN1Primitive toASN1Primitive() {
        return this;
    }

    /* access modifiers changed from: package-private */
    public ASN1Primitive toDERObject() {
        return this;
    }

    /* access modifiers changed from: package-private */
    public ASN1Primitive toDLObject() {
        return this;
    }
}
