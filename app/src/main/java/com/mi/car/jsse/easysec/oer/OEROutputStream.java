package com.mi.car.jsse.easysec.oer;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.oer.OERDefinition;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;

public class OEROutputStream extends OutputStream {
    private static final int[] bits = {1, 2, 4, 8, 16, 32, 64, 128};
    protected PrintWriter debugOutput = null;
    private final OutputStream out;

    public OEROutputStream(OutputStream out2) {
        this.out = out2;
    }

    public static int byteLength(long value) {
        int j = 8;
        while (j > 0 && (value & -72057594037927936L) == 0) {
            value <<= 8;
            j--;
        }
        return j;
    }

    /* JADX WARNING: Removed duplicated region for block: B:36:0x00ef  */
    /* JADX WARNING: Removed duplicated region for block: B:40:0x010c  */
    /* JADX WARNING: Removed duplicated region for block: B:75:0x01e5  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void write(com.mi.car.jsse.easysec.asn1.ASN1Encodable r46, Element r47) throws IOException {
        /*
        // Method dump skipped, instructions count: 2224
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.oer.OEROutputStream.write(com.mi.car.jsse.easysec.asn1.ASN1Encodable, com.mi.car.jsse.easysec.oer.Element):void");
    }

    /* access modifiers changed from: package-private */
    /* renamed from: com.mi.car.jsse.easysec.oer.OEROutputStream$1  reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType = new int[OERDefinition.BaseType.values().length];

        static {
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.Supplier.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.SEQ.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.SEQ_OF.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.CHOICE.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.ENUM.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.INT.ordinal()] = 6;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.OCTET_STRING.ordinal()] = 7;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.IA5String.ordinal()] = 8;
            } catch (NoSuchFieldError e8) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.UTF8_STRING.ordinal()] = 9;
            } catch (NoSuchFieldError e9) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.BIT_STRING.ordinal()] = 10;
            } catch (NoSuchFieldError e10) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.NULL.ordinal()] = 11;
            } catch (NoSuchFieldError e11) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.EXTENSION.ordinal()] = 12;
            } catch (NoSuchFieldError e12) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.ENUM_ITEM.ordinal()] = 13;
            } catch (NoSuchFieldError e13) {
            }
            try {
                $SwitchMap$cn$com$easysec$oer$OERDefinition$BaseType[OERDefinition.BaseType.BOOLEAN.ordinal()] = 14;
            } catch (NoSuchFieldError e14) {
            }
        }
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

    private void encodeLength(long len) throws IOException {
        if (len <= 127) {
            this.out.write((int) len);
            return;
        }
        byte[] value = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(len));
        this.out.write(value.length | 128);
        this.out.write(value);
    }

    private void encodeQuantity(long quantity) throws IOException {
        byte[] quantityEncoded = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(quantity));
        this.out.write(quantityEncoded.length);
        this.out.write(quantityEncoded);
    }

    @Override // java.io.OutputStream
    public void write(int b) throws IOException {
        this.out.write(b);
    }

    public void writePlainType(ASN1Encodable value, Element e) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        OEROutputStream oerOutputStream = new OEROutputStream(bos);
        oerOutputStream.write(value, e);
        oerOutputStream.flush();
        oerOutputStream.close();
        encodeLength((long) bos.size());
        write(bos.toByteArray());
    }
}
