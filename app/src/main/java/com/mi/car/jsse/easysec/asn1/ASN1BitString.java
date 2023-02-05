package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public abstract class ASN1BitString extends ASN1Primitive implements ASN1String, ASN1BitStringParser {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1BitString.class, 3) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1BitString.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1BitString.createPrimitive(octetString.getOctets());
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitConstructed(ASN1Sequence sequence) {
            return sequence.toASN1BitString();
        }
    };
    private static final char[] table = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    final byte[] contents;

    public static ASN1BitString getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1BitString)) {
            return (ASN1BitString) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1BitString) {
                return (ASN1BitString) primitive;
            }
        } else if (obj instanceof byte[]) {
            try {
                return (ASN1BitString) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct BIT STRING from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1BitString getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1BitString) TYPE.getContextInstance(taggedObject, explicit);
    }

    protected static int getPadBits(int bitString) {
        int val = 0;
        int i = 3;
        while (true) {
            if (i < 0) {
                break;
            }
            if (i != 0) {
                if ((bitString >> (i * 8)) != 0) {
                    val = (bitString >> (i * 8)) & GF2Field.MASK;
                    break;
                }
            } else if (bitString != 0) {
                val = bitString & GF2Field.MASK;
                break;
            }
            i--;
        }
        if (val == 0) {
            return 0;
        }
        int bits = 1;
        while (true) {
            val <<= 1;
            if ((val & GF2Field.MASK) == 0) {
                return 8 - bits;
            }
            bits++;
        }
    }

    protected static byte[] getBytes(int bitString) {
        if (bitString == 0) {
            return new byte[0];
        }
        int bytes = 4;
        int i = 3;
        while (i >= 1 && ((GF2Field.MASK << (i * 8)) & bitString) == 0) {
            bytes--;
            i--;
        }
        byte[] result = new byte[bytes];
        for (int i2 = 0; i2 < bytes; i2++) {
            result[i2] = (byte) ((bitString >> (i2 * 8)) & GF2Field.MASK);
        }
        return result;
    }

    ASN1BitString(byte data, int padBits) {
        if (padBits > 7 || padBits < 0) {
            throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0");
        }
        this.contents = new byte[]{(byte) padBits, data};
    }

    ASN1BitString(byte[] data, int padBits) {
        if (data == null) {
            throw new NullPointerException("'data' cannot be null");
        } else if (data.length == 0 && padBits != 0) {
            throw new IllegalArgumentException("zero length data with non-zero pad bits");
        } else if (padBits > 7 || padBits < 0) {
            throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0");
        } else {
            this.contents = Arrays.prepend(data, (byte) padBits);
        }
    }

    ASN1BitString(byte[] contents2, boolean check) {
        if (check) {
            if (contents2 == null) {
                throw new NullPointerException("'contents' cannot be null");
            } else if (contents2.length < 1) {
                throw new IllegalArgumentException("'contents' cannot be empty");
            } else {
                int padBits = contents2[0] & 255;
                if (padBits > 0) {
                    if (contents2.length < 2) {
                        throw new IllegalArgumentException("zero length data with non-zero pad bits");
                    } else if (padBits > 7) {
                        throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0");
                    }
                }
            }
        }
        this.contents = contents2;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitStringParser
    public InputStream getBitStream() throws IOException {
        return new ByteArrayInputStream(this.contents, 1, this.contents.length - 1);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitStringParser
    public InputStream getOctetStream() throws IOException {
        int padBits = this.contents[0] & 255;
        if (padBits == 0) {
            return getBitStream();
        }
        throw new IOException("expected octet-aligned bitstring, but found padBits: " + padBits);
    }

    public ASN1BitStringParser parser() {
        return this;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1String
    public String getString() {
        try {
            byte[] string = getEncoded();
            StringBuffer buf = new StringBuffer((string.length * 2) + 1);
            buf.append('#');
            for (int i = 0; i != string.length; i++) {
                byte b = string[i];
                buf.append(table[(b >>> 4) & 15]);
                buf.append(table[b & 15]);
            }
            return buf.toString();
        } catch (IOException e) {
            throw new ASN1ParsingException("Internal error encoding BitString: " + e.getMessage(), e);
        }
    }

    public int intValue() {
        int value = 0;
        int end = Math.min(5, this.contents.length - 1);
        for (int i = 1; i < end; i++) {
            value |= (this.contents[i] & 255) << ((i - 1) * 8);
        }
        if (1 > end || end >= 5) {
            return value;
        }
        return value | ((((byte) (this.contents[end] & (GF2Field.MASK << (this.contents[0] & 255)))) & 255) << ((end - 1) * 8));
    }

    public byte[] getOctets() {
        if (this.contents[0] == 0) {
            return Arrays.copyOfRange(this.contents, 1, this.contents.length);
        }
        throw new IllegalStateException("attempt to get non-octet aligned data from BIT STRING");
    }

    public byte[] getBytes() {
        if (this.contents.length == 1) {
            return ASN1OctetString.EMPTY_OCTETS;
        }
        int padBits = this.contents[0] & 255;
        byte[] rv = Arrays.copyOfRange(this.contents, 1, this.contents.length);
        int length = rv.length - 1;
        rv[length] = (byte) (rv[length] & ((byte) (GF2Field.MASK << padBits)));
        return rv;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1BitStringParser
    public int getPadBits() {
        return this.contents[0] & 255;
    }

    public String toString() {
        return getString();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        if (this.contents.length < 2) {
            return 1;
        }
        int padBits = this.contents[0] & 255;
        int last = this.contents.length - 1;
        return (Arrays.hashCode(this.contents, 0, last) * 257) ^ ((byte) (this.contents[last] & (GF2Field.MASK << padBits)));
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive other) {
        boolean z = true;
        if (!(other instanceof ASN1BitString)) {
            return false;
        }
        byte[] thisContents = this.contents;
        byte[] thatContents = ((ASN1BitString) other).contents;
        int length = thisContents.length;
        if (thatContents.length != length) {
            return false;
        }
        if (length == 1) {
            return true;
        }
        int last = length - 1;
        for (int i = 0; i < last; i++) {
            if (thisContents[i] != thatContents[i]) {
                return false;
            }
        }
        int padBits = thisContents[0] & 255;
        if (((byte) (thisContents[last] & (GF2Field.MASK << padBits))) != ((byte) (thatContents[last] & (GF2Field.MASK << padBits)))) {
            z = false;
        }
        return z;
    }

    @Override // com.mi.car.jsse.easysec.asn1.InMemoryRepresentable
    public ASN1Primitive getLoadedObject() {
        return toASN1Primitive();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDERObject() {
        return new DERBitString(this.contents, false);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public ASN1Primitive toDLObject() {
        return new DLBitString(this.contents, false);
    }

    static ASN1BitString createPrimitive(byte[] contents2) {
        int length = contents2.length;
        if (length < 1) {
            throw new IllegalArgumentException("truncated BIT STRING detected");
        }
        int padBits = contents2[0] & 255;
        if (padBits > 0) {
            if (padBits > 7 || length < 2) {
                throw new IllegalArgumentException("invalid pad bits detected");
            }
            byte finalOctet = contents2[length - 1];
            if (finalOctet != ((byte) ((GF2Field.MASK << padBits) & finalOctet))) {
                return new DLBitString(contents2, false);
            }
        }
        return new DERBitString(contents2, false);
    }
}
