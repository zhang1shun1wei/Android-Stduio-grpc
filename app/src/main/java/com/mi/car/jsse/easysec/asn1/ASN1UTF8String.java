package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;

public abstract class ASN1UTF8String extends ASN1Primitive implements ASN1String {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1UTF8String.class, 12) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1UTF8String.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1UTF8String.createPrimitive(octetString.getOctets());
        }
    };
    final byte[] contents;

    public static ASN1UTF8String getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1UTF8String)) {
            return (ASN1UTF8String) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1UTF8String) {
                return (ASN1UTF8String) primitive;
            }
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1UTF8String) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static ASN1UTF8String getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1UTF8String) TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1UTF8String(String string) {
        this(Strings.toUTF8ByteArray(string), false);
    }

    ASN1UTF8String(byte[] contents2, boolean clone) {
        this.contents = clone ? Arrays.clone(contents2) : contents2;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1String
    public final String getString() {
        return Strings.fromUTF8ByteArray(this.contents);
    }

    public String toString() {
        return getString();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final boolean asn1Equals(ASN1Primitive other) {
        if (!(other instanceof ASN1UTF8String)) {
            return false;
        }
        return Arrays.areEqual(this.contents, ((ASN1UTF8String) other).contents);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final boolean encodeConstructed() {
        return false;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, this.contents.length);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingDL(withTag, 12, this.contents);
    }

    static ASN1UTF8String createPrimitive(byte[] contents2) {
        return new DERUTF8String(contents2, false);
    }
}
