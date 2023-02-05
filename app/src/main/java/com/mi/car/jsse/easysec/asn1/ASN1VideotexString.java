package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;

public abstract class ASN1VideotexString extends ASN1Primitive implements ASN1String {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1VideotexString.class, 21) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1VideotexString.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1VideotexString.createPrimitive(octetString.getOctets());
        }
    };
    final byte[] contents;

    public static ASN1VideotexString getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1VideotexString)) {
            return (ASN1VideotexString) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1VideotexString) {
                return (ASN1VideotexString) primitive;
            }
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1VideotexString) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static ASN1VideotexString getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1VideotexString) TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1VideotexString(byte[] contents2, boolean clone) {
        this.contents = clone ? Arrays.clone(contents2) : contents2;
    }

    public final byte[] getOctets() {
        return Arrays.clone(this.contents);
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
        out.writeEncodingDL(withTag, 21, this.contents);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final boolean asn1Equals(ASN1Primitive other) {
        if (!(other instanceof ASN1VideotexString)) {
            return false;
        }
        return Arrays.areEqual(this.contents, ((ASN1VideotexString) other).contents);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1String
    public final String getString() {
        return Strings.fromByteArray(this.contents);
    }

    static ASN1VideotexString createPrimitive(byte[] contents2) {
        return new DERVideotexString(contents2, false);
    }
}
