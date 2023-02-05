package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.crypto.agreement.jpake.JPAKEParticipant;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;

public abstract class ASN1PrintableString extends ASN1Primitive implements ASN1String {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1PrintableString.class, 19) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1PrintableString.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1PrintableString.createPrimitive(octetString.getOctets());
        }
    };
    final byte[] contents;

    public static ASN1PrintableString getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1PrintableString)) {
            return (ASN1PrintableString) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1PrintableString) {
                return (ASN1PrintableString) primitive;
            }
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1PrintableString) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static ASN1PrintableString getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1PrintableString) TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1PrintableString(String string, boolean validate) {
        if (!validate || isPrintableString(string)) {
            this.contents = Strings.toByteArray(string);
            return;
        }
        throw new IllegalArgumentException("string contains illegal characters");
    }

    ASN1PrintableString(byte[] contents2, boolean clone) {
        this.contents = clone ? Arrays.clone(contents2) : contents2;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1String
    public final String getString() {
        return Strings.fromByteArray(this.contents);
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
        out.writeEncodingDL(withTag, 19, this.contents);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final boolean asn1Equals(ASN1Primitive other) {
        if (!(other instanceof ASN1PrintableString)) {
            return false;
        }
        return Arrays.areEqual(this.contents, ((ASN1PrintableString) other).contents);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    public String toString() {
        return getString();
    }

    public static boolean isPrintableString(String str) {
        for (int i = str.length() - 1; i >= 0; i--) {
            char ch = str.charAt(i);
            if (ch > 127) {
                return false;
            }
            if (('a' > ch || ch > 'z') && (('A' > ch || ch > 'Z') && ('0' > ch || ch > '9'))) {
                switch (ch) {
                    default:
                        return false;
                    case ' ':
                    case '\'':
                    case JPAKEParticipant.STATE_ROUND_2_VALIDATED /*{ENCODED_INT: 40}*/:
                    case ')':
                    case '+':
                    case ',':
                    case '-':
                    case '.':
                    case '/':
                    case ':':
                    case '=':
                    case '?':
                        break;
                }
            }
        }
        return true;
    }

    static ASN1PrintableString createPrimitive(byte[] contents2) {
        return new DERPrintableString(contents2, false);
    }
}
