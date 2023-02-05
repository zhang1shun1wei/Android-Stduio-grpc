package com.mi.car.jsse.easysec.oer;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.cmp.PKIFailureInfo;
import com.mi.car.jsse.easysec.asn1.eac.CertificateBody;
import com.mi.car.jsse.easysec.asn1.eac.CertificateHolderAuthorization;
import com.mi.car.jsse.easysec.oer.OERDefinition;
import com.mi.car.jsse.easysec.util.BigIntegers;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.math.BigInteger;

public class OERInputStream extends FilterInputStream {
    private static final int[] bits = {1, 2, 4, 8, 16, 32, 64, 128};
    private static final int[] bitsR = {128, 64, 32, 16, 8, 4, 2, 1};
    protected PrintWriter debugOutput = null;
    protected PrintWriter debugStream = null;
    private int maxByteAllocation = PKIFailureInfo.badCertTemplate;

    public OERInputStream(InputStream src) {
        super(src);
    }

    public OERInputStream(InputStream src, int maxByteAllocation2) {
        super(src);
        this.maxByteAllocation = maxByteAllocation2;
    }

    public static ASN1Encodable parse(byte[] src, Element element) throws IOException {
        return new OERInputStream(new ByteArrayInputStream(src)).parse(element);
    }

    private int countOptionalChildTypes(Element element) {
        int optionalElements = 0;
        for (Element e : element.getChildren()) {
            optionalElements += e.isExplicit() ? 0 : 1;
        }
        return optionalElements;
    }

    /* access modifiers changed from: package-private */
    /* renamed from: com.mi.car.jsse.easysec.oer.OERInputStream$1  reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType = new int[OERDefinition.BaseType.values().length];

        static {
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.OPAQUE.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.Switch.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.Supplier.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.SEQ_OF.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.SEQ.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.CHOICE.ordinal()] = 6;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.ENUM.ordinal()] = 7;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.INT.ordinal()] = 8;
            } catch (NoSuchFieldError e8) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.OCTET_STRING.ordinal()] = 9;
            } catch (NoSuchFieldError e9) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.IA5String.ordinal()] = 10;
            } catch (NoSuchFieldError e10) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.UTF8_STRING.ordinal()] = 11;
            } catch (NoSuchFieldError e11) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.BIT_STRING.ordinal()] = 12;
            } catch (NoSuchFieldError e12) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.NULL.ordinal()] = 13;
            } catch (NoSuchFieldError e13) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.EXTENSION.ordinal()] = 14;
            } catch (NoSuchFieldError e14) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.BOOLEAN.ordinal()] = 15;
            } catch (NoSuchFieldError e15) {
            }
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:31:0x018a  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public com.mi.car.jsse.easysec.asn1.ASN1Object parse(Element r38) throws IOException {
        /*
        // Method dump skipped, instructions count: 2084
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.oer.OERInputStream.parse(com.mi.car.jsse.easysec.oer.Element):com.mi.car.jsse.easysec.asn1.ASN1Object");
    }

    private ASN1Encodable absent(Element child) {
        debugPrint(child + "Absent");
        return OEROptional.ABSENT;
    }

    private byte[] allocateArray(int requiredSize) {
        if (requiredSize <= this.maxByteAllocation) {
            return new byte[requiredSize];
        }
        throw new IllegalArgumentException("required byte array size " + requiredSize + " was greater than " + this.maxByteAllocation);
    }

    public BigInteger parseInt(boolean unsigned, int size) throws Exception {
        byte[] buf = new byte[size];
        if (Streams.readFully(this, buf) == buf.length) {
            return unsigned ? new BigInteger(1, buf) : new BigInteger(buf);
        }
        throw new IllegalStateException("integer not fully read");
    }

    public BigInteger uint8() throws Exception {
        return parseInt(true, 1);
    }

    public BigInteger uint16() throws Exception {
        return parseInt(true, 2);
    }

    public BigInteger uint32() throws Exception {
        return parseInt(true, 4);
    }

    public BigInteger uint64() throws Exception {
        return parseInt(false, 8);
    }

    public BigInteger int8() throws Exception {
        return parseInt(false, 1);
    }

    public BigInteger int16() throws Exception {
        return parseInt(false, 2);
    }

    public BigInteger int32() throws Exception {
        return parseInt(false, 4);
    }

    public BigInteger int64() throws Exception {
        return parseInt(false, 8);
    }

    public LengthInfo readLength() throws IOException {
        int byteVal = read();
        if (byteVal == -1) {
            throw new EOFException("expecting length");
        } else if ((byteVal & 128) == 0) {
            debugPrint("Len (Short form): " + (byteVal & CertificateBody.profileType));
            return new LengthInfo(BigInteger.valueOf((long) (byteVal & CertificateBody.profileType)), true);
        } else {
            byte[] lengthInt = new byte[(byteVal & CertificateBody.profileType)];
            if (Streams.readFully(this, lengthInt) != lengthInt.length) {
                throw new EOFException("did not read all bytes of length definition");
            }
            debugPrint("Len (Long Form): " + (byteVal & CertificateBody.profileType) + " actual len: " + Hex.toHexString(lengthInt));
            return new LengthInfo(BigIntegers.fromUnsignedByteArray(lengthInt), false);
        }
    }

    public BigInteger enumeration() throws IOException {
        int first = read();
        if (first == -1) {
            throw new EOFException("expecting prefix of enumeration");
        } else if ((first & 128) != 128) {
            return BigInteger.valueOf((long) first);
        } else {
            int l = first & CertificateBody.profileType;
            if (l == 0) {
                return BigInteger.ZERO;
            }
            byte[] buf = new byte[l];
            if (Streams.readFully(this, buf) == buf.length) {
                return new BigInteger(1, buf);
            }
            throw new EOFException("unable to fully read integer component of enumeration");
        }
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Removed duplicated region for block: B:14:0x0035  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public com.mi.car.jsse.easysec.asn1.ASN1Encodable parseOpenType(Element r8) throws IOException {
        /*
            r7 = this;
            com.mi.car.jsse.easysec.oer.OERInputStream$LengthInfo r5 = r7.readLength()
            int r1 = com.mi.car.jsse.easysec.oer.OERInputStream.LengthInfo.access$000(r5)
            byte[] r4 = r7.allocateArray(r1)
            java.io.InputStream r5 = r7.in
            int r5 = com.mi.car.jsse.easysec.util.io.Streams.readFully(r5, r4)
            int r6 = r4.length
            if (r5 == r6) goto L_0x001d
            java.io.IOException r5 = new java.io.IOException
            java.lang.String r6 = "did not fully read open type as raw bytes"
            r5.<init>(r6)
            throw r5
        L_0x001d:
            r2 = 0
            java.io.ByteArrayInputStream r0 = new java.io.ByteArrayInputStream     // Catch:{ all -> 0x0032 }
            r0.<init>(r4)     // Catch:{ all -> 0x0032 }
            com.mi.car.jsse.easysec.oer.OERInputStream r3 = new com.mi.car.jsse.easysec.oer.OERInputStream     // Catch:{ all -> 0x0032 }
            r3.<init>(r0)     // Catch:{ all -> 0x0032 }
            com.mi.car.jsse.easysec.asn1.ASN1Object r5 = r3.parse(r8)     // Catch:{ all -> 0x0039 }
            if (r3 == 0) goto L_0x0031
            r3.close()
        L_0x0031:
            return r5
        L_0x0032:
            r5 = move-exception
        L_0x0033:
            if (r2 == 0) goto L_0x0038
            r2.close()
        L_0x0038:
            throw r5
        L_0x0039:
            r5 = move-exception
            r2 = r3
            goto L_0x0033
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.oer.OERInputStream.parseOpenType(com.mi.car.jsse.easysec.oer.Element):com.mi.car.jsse.easysec.asn1.ASN1Encodable");
    }

    public Choice choice() throws IOException {
        return new Choice(this);
    }

    /* access modifiers changed from: protected */
    public void debugPrint(String what) {
        if (this.debugOutput != null) {
            StackTraceElement[] callStack = Thread.currentThread().getStackTrace();
            int level = -1;
            for (int i = 0; i != callStack.length; i++) {
                StackTraceElement ste = callStack[i];
                if (ste.getMethodName().equals("debugPrint")) {
                    level = 0;
                } else if (ste.getClassName().contains("OERInput")) {
                    level++;
                }
            }
            while (level > 0) {
                this.debugOutput.append((CharSequence) "    ");
                level--;
            }
            this.debugOutput.append((CharSequence) what).append((CharSequence) "\n");
            this.debugOutput.flush();
        }
    }

    public static class Choice extends OERInputStream {
        final int preamble = read();
        final int tag;
        final int tagClass;

        public Choice(InputStream src) throws IOException {
            super(src);
            int part;
            if (this.preamble < 0) {
                throw new EOFException("expecting preamble byte of choice");
            }
            this.tagClass = this.preamble & CertificateHolderAuthorization.CVCA;
            int tag2 = this.preamble & 63;
            if (tag2 >= 63) {
                tag2 = 0;
                do {
                    part = src.read();
                    if (part < 0) {
                        throw new EOFException("expecting further tag bytes");
                    }
                    tag2 = (tag2 << 7) | (part & CertificateBody.profileType);
                } while ((part & 128) != 0);
            }
            this.tag = tag2;
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("CHOICE(");
            switch (this.tagClass) {
                case 0:
                    sb.append("Universal ");
                    break;
                case 64:
                    sb.append("Application ");
                    break;
                case 128:
                    sb.append("ContextSpecific ");
                    break;
                case CertificateHolderAuthorization.CVCA:
                    sb.append("Private ");
                    break;
            }
            sb.append("Tag = " + this.tag);
            sb.append(")");
            return sb.toString();
        }

        public int getTagClass() {
            return this.tagClass;
        }

        public int getTag() {
            return this.tag;
        }

        public boolean isContextSpecific() {
            return this.tagClass == 128;
        }

        public boolean isUniversalTagClass() {
            return this.tagClass == 0;
        }

        public boolean isApplicationTagClass() {
            return this.tagClass == 64;
        }

        public boolean isPrivateTagClass() {
            return this.tagClass == 192;
        }
    }

    public static class Sequence extends OERInputStream {
        private final boolean extensionFlagSet;
        private final int preamble;
        private final boolean[] valuePresent;

        public Sequence(InputStream src, Element element) throws IOException {
            super(src);
            if (element.hasPopulatedExtension() || element.getOptionals() > 0 || element.hasDefaultChildren()) {
                this.preamble = this.in.read();
                if (this.preamble < 0) {
                    throw new EOFException("expecting preamble byte of sequence");
                }
                this.extensionFlagSet = element.hasPopulatedExtension() && (this.preamble & 128) == 128;
                this.valuePresent = new boolean[element.getChildren().size()];
                int j = element.hasPopulatedExtension() ? 6 : 7;
                int mask = this.preamble;
                int presentIndex = 0;
                for (Element child : element.getChildren()) {
                    if (child.getBaseType() != OERDefinition.BaseType.EXTENSION) {
                        if (child.getBlock() != 0) {
                            return;
                        }
                        if (child.isExplicit()) {
                            this.valuePresent[presentIndex] = true;
                            presentIndex++;
                        } else {
                            if (j < 0) {
                                mask = src.read();
                                if (mask < 0) {
                                    throw new EOFException("expecting mask byte sequence");
                                }
                                j = 7;
                            }
                            int presentIndex2 = presentIndex + 1;
                            this.valuePresent[presentIndex] = (OERInputStream.bits[j] & mask) > 0;
                            j--;
                            presentIndex = presentIndex2;
                        }
                    }
                }
                return;
            }
            this.preamble = 0;
            this.extensionFlagSet = false;
            this.valuePresent = null;
        }

        public boolean hasOptional(int index) {
            return this.valuePresent[index];
        }

        public boolean hasExtension() {
            return this.extensionFlagSet;
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("SEQ(");
            sb.append(hasExtension() ? "Ext " : "");
            if (this.valuePresent == null) {
                sb.append("*");
            } else {
                for (int t = 0; t < this.valuePresent.length; t++) {
                    if (this.valuePresent[t]) {
                        sb.append("1");
                    } else {
                        sb.append("0");
                    }
                }
            }
            sb.append(")");
            return sb.toString();
        }
    }

    /* access modifiers changed from: private */
    public final class LengthInfo {
        private final BigInteger length;
        private final boolean shortForm;

        public LengthInfo(BigInteger length2, boolean shortForm2) {
            this.length = length2;
            this.shortForm = shortForm2;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private int intLength() {
            return BigIntegers.intValueExact(this.length);
        }
    }
}
