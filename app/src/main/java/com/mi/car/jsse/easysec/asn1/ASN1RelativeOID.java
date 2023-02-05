package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class ASN1RelativeOID extends ASN1Primitive {
    private static final long LONG_LIMIT = 72057594037927808L;
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1RelativeOID.class, 13) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1RelativeOID.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1RelativeOID.createPrimitive(octetString.getOctets(), false);
        }
    };
    private byte[] contents;
    private final String identifier;

    public static ASN1RelativeOID fromContents(byte[] contents2) {
        return createPrimitive(contents2, true);
    }

    public static ASN1RelativeOID getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1RelativeOID)) {
            return (ASN1RelativeOID) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1RelativeOID) {
                return (ASN1RelativeOID) primitive;
            }
        } else if (obj instanceof byte[]) {
            try {
                return (ASN1RelativeOID) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct relative OID from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1RelativeOID getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1RelativeOID) TYPE.getContextInstance(taggedObject, explicit);
    }

    public ASN1RelativeOID(String identifier2) {
        if (identifier2 == null) {
            throw new NullPointerException("'identifier' cannot be null");
        } else if (!isValidIdentifier(identifier2, 0)) {
            throw new IllegalArgumentException("string " + identifier2 + " not a relative OID");
        } else {
            this.identifier = identifier2;
        }
    }

    ASN1RelativeOID(ASN1RelativeOID oid, String branchID) {
        if (!isValidIdentifier(branchID, 0)) {
            throw new IllegalArgumentException("string " + branchID + " not a valid OID branch");
        }
        this.identifier = oid.getId() + "." + branchID;
    }

    private ASN1RelativeOID(byte[] contents2, boolean clone) {
        StringBuffer objId = new StringBuffer();
        long value = 0;
        BigInteger bigValue = null;
        boolean first = true;
        for (int i = 0; i != contents2.length; i++) {
            int b = contents2[i] & 255;
            if (value <= LONG_LIMIT) {
                long value2 = value + ((long) (b & 127));
                if ((b & 128) == 0) {
                    if (first) {
                        first = false;
                    } else {
                        objId.append('.');
                    }
                    objId.append(value2);
                    value = 0;
                } else {
                    value = value2 << 7;
                }
            } else {
                BigInteger bigValue2 = (bigValue == null ? BigInteger.valueOf(value) : bigValue).or(BigInteger.valueOf((long) (b & 127)));
                if ((b & 128) == 0) {
                    if (first) {
                        first = false;
                    } else {
                        objId.append('.');
                    }
                    objId.append(bigValue2);
                    bigValue = null;
                    value = 0;
                } else {
                    bigValue = bigValue2.shiftLeft(7);
                }
            }
        }
        this.identifier = objId.toString();
        this.contents = clone ? Arrays.clone(contents2) : contents2;
    }

    public ASN1RelativeOID branch(String branchID) {
        return new ASN1RelativeOID(this, branchID);
    }

    public String getId() {
        return this.identifier;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        return this.identifier.hashCode();
    }

    public String toString() {
        return getId();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ASN1RelativeOID)) {
            return false;
        }
        return this.identifier.equals(((ASN1RelativeOID) other).identifier);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, getContents().length);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingDL(withTag, 13, getContents());
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return false;
    }

    private void doOutput(ByteArrayOutputStream aOut) {
        OIDTokenizer tok = new OIDTokenizer(this.identifier);
        while (tok.hasMoreTokens()) {
            String token = tok.nextToken();
            if (token.length() <= 18) {
                writeField(aOut, Long.parseLong(token));
            } else {
                writeField(aOut, new BigInteger(token));
            }
        }
    }

    private synchronized byte[] getContents() {
        if (this.contents == null) {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            doOutput(bOut);
            this.contents = bOut.toByteArray();
        }
        return this.contents;
    }

    static ASN1RelativeOID createPrimitive(byte[] contents2, boolean clone) {
        return new ASN1RelativeOID(contents2, clone);
    }

    static boolean isValidIdentifier(String identifier2, int from) {
        int digitCount = 0;
        int pos = identifier2.length();
        while (true) {
            pos--;
            if (pos >= from) {
                char ch = identifier2.charAt(pos);
                if (ch == '.') {
                    if (digitCount == 0) {
                        return false;
                    }
                    if (digitCount > 1 && identifier2.charAt(pos + 1) == '0') {
                        return false;
                    }
                    digitCount = 0;
                } else if ('0' > ch || ch > '9') {
                    return false;
                } else {
                    digitCount++;
                }
            } else if (digitCount != 0) {
                return digitCount <= 1 || identifier2.charAt(pos + 1) != '0';
            } else {
                return false;
            }
        }
    }

    static void writeField(ByteArrayOutputStream out, long fieldValue) {
        byte[] result = new byte[9];
        int pos = 8;
        result[8] = (byte) (((int) fieldValue) & 127);
        while (fieldValue >= 128) {
            fieldValue >>= 7;
            pos--;
            result[pos] = (byte) (((int) fieldValue) | 128);
        }
        out.write(result, pos, 9 - pos);
    }

    static void writeField(ByteArrayOutputStream out, BigInteger fieldValue) {
        int byteCount = (fieldValue.bitLength() + 6) / 7;
        if (byteCount == 0) {
            out.write(0);
            return;
        }
        BigInteger tmpValue = fieldValue;
        byte[] tmp = new byte[byteCount];
        for (int i = byteCount - 1; i >= 0; i--) {
            tmp[i] = (byte) (tmpValue.intValue() | 128);
            tmpValue = tmpValue.shiftRight(7);
        }
        int i2 = byteCount - 1;
        tmp[i2] = (byte) (tmp[i2] & Byte.MAX_VALUE);
        out.write(tmp, 0, tmp.length);
    }
}
