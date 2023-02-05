package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.math.BigInteger;

public class ASN1Enumerated extends ASN1Primitive {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Enumerated.class, 10) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1Enumerated.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1Enumerated.createPrimitive(octetString.getOctets(), false);
        }
    };
    private static final ASN1Enumerated[] cache = new ASN1Enumerated[12];
    private final byte[] contents;
    private final int start;

    public static ASN1Enumerated getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1Enumerated)) {
            return (ASN1Enumerated) obj;
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1Enumerated) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static ASN1Enumerated getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1Enumerated) TYPE.getContextInstance(taggedObject, explicit);
    }

    public ASN1Enumerated(int value) {
        if (value < 0) {
            throw new IllegalArgumentException("enumerated must be non-negative");
        }
        this.contents = BigInteger.valueOf((long) value).toByteArray();
        this.start = 0;
    }

    public ASN1Enumerated(BigInteger value) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("enumerated must be non-negative");
        }
        this.contents = value.toByteArray();
        this.start = 0;
    }

    public ASN1Enumerated(byte[] contents2) {
        this(contents2, true);
    }

    ASN1Enumerated(byte[] contents2, boolean clone) {
        byte[] bArr;
        if (ASN1Integer.isMalformed(contents2)) {
            throw new IllegalArgumentException("malformed enumerated");
        } else if ((contents2[0] & 128) != 0) {
            throw new IllegalArgumentException("enumerated must be non-negative");
        } else {
            if (clone) {
                bArr = Arrays.clone(contents2);
            } else {
                bArr = contents2;
            }
            this.contents = bArr;
            this.start = ASN1Integer.signBytesToSkip(contents2);
        }
    }

    public BigInteger getValue() {
        return new BigInteger(this.contents);
    }

    public boolean hasValue(int x) {
        return this.contents.length - this.start <= 4 && ASN1Integer.intValue(this.contents, this.start, -1) == x;
    }

    public boolean hasValue(BigInteger x) {
        return x != null && ASN1Integer.intValue(this.contents, this.start, -1) == x.intValue() && getValue().equals(x);
    }

    public int intValueExact() {
        if (this.contents.length - this.start <= 4) {
            return ASN1Integer.intValue(this.contents, this.start, -1);
        }
        throw new ArithmeticException("ASN.1 Enumerated out of int range");
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return false;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, this.contents.length);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingDL(withTag, 10, this.contents);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive o) {
        if (!(o instanceof ASN1Enumerated)) {
            return false;
        }
        return Arrays.areEqual(this.contents, ((ASN1Enumerated) o).contents);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    static ASN1Enumerated createPrimitive(byte[] contents2, boolean clone) {
        if (contents2.length > 1) {
            return new ASN1Enumerated(contents2, clone);
        }
        if (contents2.length == 0) {
            throw new IllegalArgumentException("ENUMERATED has zero length");
        }
        int value = contents2[0] & 255;
        if (value >= cache.length) {
            return new ASN1Enumerated(contents2, clone);
        }
        ASN1Enumerated possibleMatch = cache[value];
        if (possibleMatch != null) {
            return possibleMatch;
        }
        ASN1Enumerated[] aSN1EnumeratedArr = cache;
        ASN1Enumerated possibleMatch2 = new ASN1Enumerated(contents2, clone);
        aSN1EnumeratedArr[value] = possibleMatch2;
        return possibleMatch2;
    }
}
