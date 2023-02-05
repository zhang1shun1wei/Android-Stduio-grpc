package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public abstract class ASN1BMPString extends ASN1Primitive implements ASN1String {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1BMPString.class, 30) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1BMPString.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1BMPString.createPrimitive(octetString.getOctets());
        }
    };
    final char[] string;

    public static ASN1BMPString getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1BMPString)) {
            return (ASN1BMPString) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1BMPString) {
                return (ASN1BMPString) primitive;
            }
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1BMPString) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static ASN1BMPString getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1BMPString) TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1BMPString(String string2) {
        if (string2 == null) {
            throw new NullPointerException("'string' cannot be null");
        }
        this.string = string2.toCharArray();
    }

    ASN1BMPString(byte[] string2) {
        if (string2 == null) {
            throw new NullPointerException("'string' cannot be null");
        }
        int byteLen = string2.length;
        if ((byteLen & 1) != 0) {
            throw new IllegalArgumentException("malformed BMPString encoding encountered");
        }
        int charLen = byteLen / 2;
        char[] cs = new char[charLen];
        for (int i = 0; i != charLen; i++) {
            cs[i] = (char) ((string2[i * 2] << 8) | (string2[(i * 2) + 1] & 255));
        }
        this.string = cs;
    }

    ASN1BMPString(char[] string2) {
        if (string2 == null) {
            throw new NullPointerException("'string' cannot be null");
        }
        this.string = string2;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1String
    public final String getString() {
        return new String(this.string);
    }

    public String toString() {
        return getString();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final boolean asn1Equals(ASN1Primitive other) {
        if (!(other instanceof ASN1BMPString)) {
            return false;
        }
        return Arrays.areEqual(this.string, ((ASN1BMPString) other).string);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final int hashCode() {
        return Arrays.hashCode(this.string);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final boolean encodeConstructed() {
        return false;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, this.string.length * 2);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public final void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        int count = this.string.length;
        out.writeIdentifier(withTag, 30);
        out.writeDL(count * 2);
        byte[] buf = new byte[8];
        int i = 0;
        int limit = count & -4;
        while (i < limit) {
            char c0 = this.string[i];
            char c1 = this.string[i + 1];
            char c2 = this.string[i + 2];
            char c3 = this.string[i + 3];
            i += 4;
            buf[0] = (byte) (c0 >> '\b');
            buf[1] = (byte) c0;
            buf[2] = (byte) (c1 >> '\b');
            buf[3] = (byte) c1;
            buf[4] = (byte) (c2 >> '\b');
            buf[5] = (byte) c2;
            buf[6] = (byte) (c3 >> '\b');
            buf[7] = (byte) c3;
            out.write(buf, 0, 8);
        }
        if (i < count) {
            int bufPos = 0;
            do {
                char c02 = this.string[i];
                i++;
                int bufPos2 = bufPos + 1;
                buf[bufPos] = (byte) (c02 >> '\b');
                bufPos = bufPos2 + 1;
                buf[bufPos2] = (byte) c02;
            } while (i < count);
            out.write(buf, 0, bufPos);
        }
    }

    static ASN1BMPString createPrimitive(byte[] contents) {
        return new DERBMPString(contents);
    }

    static ASN1BMPString createPrimitive(char[] string2) {
        return new DERBMPString(string2);
    }
}
