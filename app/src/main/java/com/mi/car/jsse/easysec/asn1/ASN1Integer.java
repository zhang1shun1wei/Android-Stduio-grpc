package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Properties;
import java.io.IOException;
import java.math.BigInteger;

public class ASN1Integer extends ASN1Primitive {
    static final int SIGN_EXT_SIGNED = -1;
    static final int SIGN_EXT_UNSIGNED = 255;
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Integer.class, 2) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1Integer.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1Integer.createPrimitive(octetString.getOctets());
        }
    };
    private final byte[] bytes;
    private final int start;

    public static ASN1Integer getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1Integer)) {
            return (ASN1Integer) obj;
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1Integer) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static ASN1Integer getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1Integer) TYPE.getContextInstance(taggedObject, explicit);
    }

    public ASN1Integer(long value) {
        this.bytes = BigInteger.valueOf(value).toByteArray();
        this.start = 0;
    }

    public ASN1Integer(BigInteger value) {
        this.bytes = value.toByteArray();
        this.start = 0;
    }

    public ASN1Integer(byte[] bytes2) {
        this(bytes2, true);
    }

    ASN1Integer(byte[] bytes2, boolean clone) {
        byte[] bArr;
        if (isMalformed(bytes2)) {
            throw new IllegalArgumentException("malformed integer");
        }
        if (clone) {
            bArr = Arrays.clone(bytes2);
        } else {
            bArr = bytes2;
        }
        this.bytes = bArr;
        this.start = signBytesToSkip(bytes2);
    }

    public BigInteger getPositiveValue() {
        return new BigInteger(1, this.bytes);
    }

    public BigInteger getValue() {
        return new BigInteger(this.bytes);
    }

    public boolean hasValue(int x) {
        return this.bytes.length - this.start <= 4 && intValue(this.bytes, this.start, SIGN_EXT_SIGNED) == x;
    }

    public boolean hasValue(long x) {
        return this.bytes.length - this.start <= 8 && longValue(this.bytes, this.start, SIGN_EXT_SIGNED) == x;
    }

    public boolean hasValue(BigInteger x) {
        return x != null && intValue(this.bytes, this.start, SIGN_EXT_SIGNED) == x.intValue() && getValue().equals(x);
    }

    public int intPositiveValueExact() {
        int count = this.bytes.length - this.start;
        if (count <= 4 && (count != 4 || (this.bytes[this.start] & 128) == 0)) {
            return intValue(this.bytes, this.start, 255);
        }
        throw new ArithmeticException("ASN.1 Integer out of positive int range");
    }

    public int intValueExact() {
        if (this.bytes.length - this.start <= 4) {
            return intValue(this.bytes, this.start, SIGN_EXT_SIGNED);
        }
        throw new ArithmeticException("ASN.1 Integer out of int range");
    }

    public long longValueExact() {
        if (this.bytes.length - this.start <= 8) {
            return longValue(this.bytes, this.start, SIGN_EXT_SIGNED);
        }
        throw new ArithmeticException("ASN.1 Integer out of long range");
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return false;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, this.bytes.length);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingDL(withTag, 2, this.bytes);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        return Arrays.hashCode(this.bytes);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive o) {
        if (!(o instanceof ASN1Integer)) {
            return false;
        }
        return Arrays.areEqual(this.bytes, ((ASN1Integer) o).bytes);
    }

    public String toString() {
        return getValue().toString();
    }

    static ASN1Integer createPrimitive(byte[] contents) {
        return new ASN1Integer(contents, false);
    }

    static int intValue(byte[] bytes2, int start2, int signExt) {
        int length = bytes2.length;
        int pos = Math.max(start2, length - 4);
        int val = bytes2[pos] & signExt;
        while (true) {
            pos++;
            if (pos >= length) {
                return val;
            }
            val = (val << 8) | (bytes2[pos] & 255);
        }
    }

    static long longValue(byte[] bytes2, int start2, int signExt) {
        int length = bytes2.length;
        int pos = Math.max(start2, length - 8);
        long val = (long) (bytes2[pos] & signExt);
        while (true) {
            pos++;
            if (pos >= length) {
                return val;
            }
            val = (val << 8) | ((long) (bytes2[pos] & 255));
        }
    }

    static boolean isMalformed(byte[] bytes2) {
        switch (bytes2.length) {
            case 0:
                return true;
            case 1:
                return false;
            default:
                return bytes2[0] == (bytes2[1] >> 7) && !Properties.isOverrideSet("com.mi.car.jsse.easysec.asn1.allow_unsafe_integer");
        }
    }

    static int signBytesToSkip(byte[] bytes2) {
        int pos = 0;
        int last = bytes2.length + SIGN_EXT_SIGNED;
        while (pos < last && bytes2[pos] == (bytes2[pos + 1] >> 7)) {
            pos++;
        }
        return pos;
    }
}
