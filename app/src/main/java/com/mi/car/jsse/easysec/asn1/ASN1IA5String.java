package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;

public abstract class ASN1IA5String extends ASN1Primitive implements ASN1String {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1IA5String.class, 22) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1IA5String.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1IA5String.createPrimitive(octetString.getOctets());
        }
    };
    final byte[] contents;

    public static ASN1IA5String getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1IA5String)) {
            return (ASN1IA5String) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1IA5String) {
                return (ASN1IA5String) primitive;
            }
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1IA5String) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static ASN1IA5String getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1IA5String) TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1IA5String(String string, boolean validate) {
        if (string == null) {
            throw new NullPointerException("'string' cannot be null");
        } else if (!validate || isIA5String(string)) {
            this.contents = Strings.toByteArray(string);
        } else {
            throw new IllegalArgumentException("'string' contains illegal characters");
        }
    }

    ASN1IA5String(byte[] contents2, boolean clone) {
        this.contents = clone ? Arrays.clone(contents2) : contents2;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1String
    public final String getString() {
        return Strings.fromByteArray(this.contents);
    }

    public String toString() {
        return getString();
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
        out.writeEncodingDL(withTag, 22, this.contents);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final boolean asn1Equals(ASN1Primitive other) {
        if (!(other instanceof ASN1IA5String)) {
            return false;
        }
        return Arrays.areEqual(this.contents, ((ASN1IA5String) other).contents);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    public static boolean isIA5String(String str) {
        for (int i = str.length() - 1; i >= 0; i--) {
            if (str.charAt(i) > 127) {
                return false;
            }
        }
        return true;
    }

    static ASN1IA5String createPrimitive(byte[] contents2) {
        return new DERIA5String(contents2, false);
    }
}
