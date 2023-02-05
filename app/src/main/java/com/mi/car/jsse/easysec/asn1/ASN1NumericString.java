package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.crypto.agreement.jpake.JPAKEParticipant;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;

public abstract class ASN1NumericString extends ASN1Primitive implements ASN1String {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1NumericString.class, 18) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1NumericString.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1NumericString.createPrimitive(octetString.getOctets());
        }
    };
    final byte[] contents;

    public static ASN1NumericString getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1NumericString)) {
            return (ASN1NumericString) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1NumericString) {
                return (ASN1NumericString) primitive;
            }
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1NumericString) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static ASN1NumericString getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1NumericString) TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1NumericString(String string, boolean validate) {
        if (!validate || isNumericString(string)) {
            this.contents = Strings.toByteArray(string);
            return;
        }
        throw new IllegalArgumentException("string contains illegal characters");
    }

    ASN1NumericString(byte[] contents2, boolean clone) {
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
        out.writeEncodingDL(withTag, 18, this.contents);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final boolean asn1Equals(ASN1Primitive other) {
        if (!(other instanceof ASN1NumericString)) {
            return false;
        }
        return Arrays.areEqual(this.contents, ((ASN1NumericString) other).contents);
    }

    public static boolean isNumericString(String str) {
        for (int i = str.length() - 1; i >= 0; i--) {
            char ch = str.charAt(i);
            if (ch > 127) {
                return false;
            }
            if (('0' > ch || ch > '9') && ch != ' ') {
                return false;
            }
        }
        return true;
    }

    static boolean isNumericString(byte[] contents2) {
        for (byte b : contents2) {
            switch (b) {
                case 32:
                case 48:
                case 49:
                case 50:
                case 51:
                case 52:
                case 53:
                case 54:
                case 55:
                case 56:
                case 57:
                case 33:
                case 34:
                case 35:
                case 36:
                case 37:
                case 38:
                case 39:
                case JPAKEParticipant.STATE_ROUND_2_VALIDATED /*{ENCODED_INT: 40}*/:
                case 41:
                case 42:
                case 43:
                case 44:
                case 45:
                case 46:
                case 47:
                default:
                    return false;
            }
        }
        return true;
    }

    static ASN1NumericString createPrimitive(byte[] contents2) {
        return new DERNumericString(contents2, false);
    }
}
