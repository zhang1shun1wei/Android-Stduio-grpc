package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public abstract class ASN1UniversalString extends ASN1Primitive implements ASN1String {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1UniversalString.class, 28) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1UniversalString.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1UniversalString.createPrimitive(octetString.getOctets());
        }
    };
    private static final char[] table = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    final byte[] contents;

    public static ASN1UniversalString getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1UniversalString)) {
            return (ASN1UniversalString) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1UniversalString) {
                return (ASN1UniversalString) primitive;
            }
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1UniversalString) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static ASN1UniversalString getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1UniversalString) TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1UniversalString(byte[] contents2, boolean clone) {
        this.contents = clone ? Arrays.clone(contents2) : contents2;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1String
    public final String getString() {
        int dl = this.contents.length;
        StringBuffer buf = new StringBuffer(((ASN1OutputStream.getLengthOfDL(dl) + dl) * 2) + 3);
        buf.append("#1C");
        encodeHexDL(buf, dl);
        for (int i = 0; i < dl; i++) {
            encodeHexByte(buf, this.contents[i]);
        }
        return buf.toString();
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
        out.writeEncodingDL(withTag, 28, this.contents);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final boolean asn1Equals(ASN1Primitive other) {
        if (!(other instanceof ASN1UniversalString)) {
            return false;
        }
        return Arrays.areEqual(this.contents, ((ASN1UniversalString) other).contents);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    static ASN1UniversalString createPrimitive(byte[] contents2) {
        return new DERUniversalString(contents2, false);
    }

    private static void encodeHexByte(StringBuffer buf, int i) {
        buf.append(table[(i >>> 4) & 15]);
        buf.append(table[i & 15]);
    }

    private static void encodeHexDL(StringBuffer buf, int dl) {
        if (dl < 128) {
            encodeHexByte(buf, dl);
            return;
        }
        byte[] stack = new byte[5];
        int pos = 5;
        do {
            pos--;
            stack[pos] = (byte) dl;
            dl >>>= 8;
        } while (dl != 0);
        int count = stack.length - pos;
        int pos2 = pos - 1;
        stack[pos2] = (byte) (count | 128);
        while (true) {
            int pos3 = pos2 + 1;
            encodeHexByte(buf, stack[pos2]);
            if (pos3 < stack.length) {
                pos2 = pos3;
            } else {
                return;
            }
        }
    }
}
