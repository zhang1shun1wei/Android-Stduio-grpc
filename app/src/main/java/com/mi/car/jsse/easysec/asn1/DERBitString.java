package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import java.io.IOException;

public class DERBitString extends ASN1BitString {
    public static DERBitString convert(ASN1BitString bitString) {
        return (DERBitString) bitString.toDERObject();
    }

    public static DERBitString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERBitString)) {
            return (DERBitString) obj;
        }
        if (obj instanceof ASN1BitString) {
            return convert((ASN1BitString) obj);
        }
        if (obj instanceof byte[]) {
            try {
                return convert((ASN1BitString) fromByteArray((byte[]) obj));
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static DERBitString getInstance(ASN1TaggedObject obj, boolean explicit) {
        ASN1Primitive o = obj.getObject();
        if (explicit || (o instanceof DERBitString)) {
            return getInstance((Object) o);
        }
        return fromOctetString(ASN1OctetString.getInstance(o));
    }

    public DERBitString(byte[] data) {
        this(data, 0);
    }

    public DERBitString(byte data, int padBits) {
        super(data, padBits);
    }

    public DERBitString(byte[] data, int padBits) {
        super(data, padBits);
    }

    public DERBitString(int value) {
        super(getBytes(value), getPadBits(value));
    }

    public DERBitString(ASN1Encodable obj) throws IOException {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    DERBitString(byte[] contents, boolean check) {
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
        int padBits = this.contents[0] & 255;
        int last = this.contents.length - 1;
        byte lastOctet = this.contents[last];
        byte lastOctetDER = (byte) (this.contents[last] & (GF2Field.MASK << padBits));
        if (lastOctet == lastOctetDER) {
            out.writeEncodingDL(withTag, 3, this.contents);
        } else {
            out.writeEncodingDL(withTag, 3, this.contents, 0, last, lastOctetDER);
        }
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitString, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return this;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitString, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return this;
    }

    static DERBitString fromOctetString(ASN1OctetString octetString) {
        return new DERBitString(octetString.getOctets(), true);
    }
}
