package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class ASN1ObjectIdentifier extends ASN1Primitive {
    private static final long LONG_LIMIT = 72057594037927808L;
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1ObjectIdentifier.class, 6) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1ObjectIdentifier.createPrimitive(octetString.getOctets(), false);
        }
    };
    private static final ConcurrentMap<OidHandle, ASN1ObjectIdentifier> pool = new ConcurrentHashMap();
    private byte[] contents;
    private final String identifier;

    public static ASN1ObjectIdentifier fromContents(byte[] contents2) {
        return createPrimitive(contents2, true);
    }

    public static ASN1ObjectIdentifier getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1ObjectIdentifier)) {
            return (ASN1ObjectIdentifier) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (primitive instanceof ASN1ObjectIdentifier) {
                return (ASN1ObjectIdentifier) primitive;
            }
        } else if (obj instanceof byte[]) {
            try {
                return (ASN1ObjectIdentifier) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct object identifier from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1ObjectIdentifier getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        if (!explicit && !taggedObject.isParsed()) {
            ASN1Primitive base = taggedObject.getObject();
            if (!(base instanceof ASN1ObjectIdentifier)) {
                return fromContents(ASN1OctetString.getInstance(base).getOctets());
            }
        }
        return (ASN1ObjectIdentifier) TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1ObjectIdentifier(byte[] contents2, boolean clone) {
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
                        if (value2 < 40) {
                            objId.append('0');
                        } else if (value2 < 80) {
                            objId.append('1');
                            value2 -= 40;
                        } else {
                            objId.append('2');
                            value2 -= 80;
                        }
                        first = false;
                    }
                    objId.append('.');
                    objId.append(value2);
                    value = 0;
                } else {
                    value = value2 << 7;
                }
            } else {
                BigInteger bigValue2 = (bigValue == null ? BigInteger.valueOf(value) : bigValue).or(BigInteger.valueOf((long) (b & 127)));
                if ((b & 128) == 0) {
                    if (first) {
                        objId.append('2');
                        bigValue2 = bigValue2.subtract(BigInteger.valueOf(80));
                        first = false;
                    }
                    objId.append('.');
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

    public ASN1ObjectIdentifier(String identifier2) {
        if (identifier2 == null) {
            throw new NullPointerException("'identifier' cannot be null");
        } else if (!isValidIdentifier(identifier2)) {
            throw new IllegalArgumentException("string " + identifier2 + " not an OID");
        } else {
            this.identifier = identifier2;
        }
    }

    ASN1ObjectIdentifier(ASN1ObjectIdentifier oid, String branchID) {
        if (!ASN1RelativeOID.isValidIdentifier(branchID, 0)) {
            throw new IllegalArgumentException("string " + branchID + " not a valid OID branch");
        }
        this.identifier = oid.getId() + "." + branchID;
    }

    public String getId() {
        return this.identifier;
    }

    public ASN1ObjectIdentifier branch(String branchID) {
        return new ASN1ObjectIdentifier(this, branchID);
    }

    public boolean on(ASN1ObjectIdentifier stem) {
        String id = getId();
        String stemId = stem.getId();
        return id.length() > stemId.length() && id.charAt(stemId.length()) == '.' && id.startsWith(stemId);
    }

    private void doOutput(ByteArrayOutputStream aOut) {
        OIDTokenizer tok = new OIDTokenizer(this.identifier);
        int first = Integer.parseInt(tok.nextToken()) * 40;
        String secondToken = tok.nextToken();
        if (secondToken.length() <= 18) {
            ASN1RelativeOID.writeField(aOut, ((long) first) + Long.parseLong(secondToken));
        } else {
            ASN1RelativeOID.writeField(aOut, new BigInteger(secondToken).add(BigInteger.valueOf((long) first)));
        }
        while (tok.hasMoreTokens()) {
            String token = tok.nextToken();
            if (token.length() <= 18) {
                ASN1RelativeOID.writeField(aOut, Long.parseLong(token));
            } else {
                ASN1RelativeOID.writeField(aOut, new BigInteger(token));
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

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return false;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, getContents().length);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingDL(withTag, 6, getContents());
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        return this.identifier.hashCode();
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof ASN1ObjectIdentifier)) {
            return false;
        }
        return this.identifier.equals(((ASN1ObjectIdentifier) o).identifier);
    }

    public String toString() {
        return getId();
    }

    private static boolean isValidIdentifier(String identifier2) {
        char first;
        if (identifier2.length() < 3 || identifier2.charAt(1) != '.' || (first = identifier2.charAt(0)) < '0' || first > '2') {
            return false;
        }
        return ASN1RelativeOID.isValidIdentifier(identifier2, 2);
    }

    public ASN1ObjectIdentifier intern() {
        OidHandle hdl = new OidHandle(getContents());
        ASN1ObjectIdentifier oid = pool.get(hdl);
        if (oid != null) {
            return oid;
        }
        ASN1ObjectIdentifier oid2 = pool.putIfAbsent(hdl, this);
        return oid2 == null ? this : oid2;
    }

    /* access modifiers changed from: private */
    public static class OidHandle {
        private final byte[] contents;
        private final int key;

        OidHandle(byte[] contents2) {
            this.key = Arrays.hashCode(contents2);
            this.contents = contents2;
        }

        public int hashCode() {
            return this.key;
        }

        public boolean equals(Object o) {
            if (o instanceof OidHandle) {
                return Arrays.areEqual(this.contents, ((OidHandle) o).contents);
            }
            return false;
        }
    }

    static ASN1ObjectIdentifier createPrimitive(byte[] contents2, boolean clone) {
        ASN1ObjectIdentifier oid = pool.get(new OidHandle(contents2));
        if (oid == null) {
            return new ASN1ObjectIdentifier(contents2, clone);
        }
        return oid;
    }
}
