package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public class ASN1Boolean extends ASN1Primitive {
    private static final byte FALSE_VALUE = 0;
    private static final byte TRUE_VALUE = -1;
    public static final ASN1Boolean FALSE = new ASN1Boolean(FALSE_VALUE);
    public static final ASN1Boolean TRUE = new ASN1Boolean(TRUE_VALUE);
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Boolean.class, 1) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1Boolean.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1Boolean.createPrimitive(octetString.getOctets());
        }
    };
    private final byte value;

    public static ASN1Boolean getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1Boolean)) {
            return (ASN1Boolean) obj;
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1Boolean) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct boolean from byte[]: " + e.getMessage());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static ASN1Boolean getInstance(boolean value2) {
        return value2 ? TRUE : FALSE;
    }

    public static ASN1Boolean getInstance(int value2) {
        return value2 != 0 ? TRUE : FALSE;
    }

    public static ASN1Boolean getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1Boolean) TYPE.getContextInstance(taggedObject, explicit);
    }

    private ASN1Boolean(byte value2) {
        this.value = value2;
    }

    public boolean isTrue() {
        return this.value != 0;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return false;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, 1);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingDL(withTag, 1, this.value);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive other) {
        if ((other instanceof ASN1Boolean) && isTrue() == ((ASN1Boolean) other).isTrue()) {
            return true;
        }
        return false;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        return isTrue() ? 1 : 0;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return isTrue() ? TRUE : FALSE;
    }

    public String toString() {
        return isTrue() ? "TRUE" : "FALSE";
    }

    static ASN1Boolean createPrimitive(byte[] contents) {
        if (contents.length != 1) {
            throw new IllegalArgumentException("BOOLEAN value should have 1 byte in it");
        }
        byte b = contents[0];
        switch (b) {
            case -1:
                return TRUE;
            case 0:
                return FALSE;
            default:
                return new ASN1Boolean(b);
        }
    }
}
