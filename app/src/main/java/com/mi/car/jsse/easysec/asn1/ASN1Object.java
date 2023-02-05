package com.mi.car.jsse.easysec.asn1;

import com.mi.car.jsse.easysec.util.Encodable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public abstract class ASN1Object implements ASN1Encodable, Encodable {
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public abstract ASN1Primitive toASN1Primitive();

    public void encodeTo(OutputStream output) throws IOException {
        toASN1Primitive().encodeTo(output);
    }

    public void encodeTo(OutputStream output, String encoding) throws IOException {
        toASN1Primitive().encodeTo(output, encoding);
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable
    public byte[] getEncoded() throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        toASN1Primitive().encodeTo(bOut);
        return bOut.toByteArray();
    }

    public byte[] getEncoded(String encoding) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        toASN1Primitive().encodeTo(bOut, encoding);
        return bOut.toByteArray();
    }

    public int hashCode() {
        return toASN1Primitive().hashCode();
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ASN1Encodable)) {
            return false;
        }
        return toASN1Primitive().equals(((ASN1Encodable) o).toASN1Primitive());
    }

    /*  JADX ERROR: JadxRuntimeException in pass: ModVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Can't change immutable type byte[] to java.lang.Object for r2v2 byte[]
        	at jadx.core.dex.instructions.args.SSAVar.setType(SSAVar.java:100)
        	at jadx.core.dex.instructions.args.RegisterArg.setType(RegisterArg.java:52)
        	at jadx.core.dex.visitors.ModVisitor.removeCheckCast(ModVisitor.java:358)
        	at jadx.core.dex.visitors.ModVisitor.replaceStep(ModVisitor.java:144)
        	at jadx.core.dex.visitors.ModVisitor.visit(ModVisitor.java:93)
        */
    protected static boolean hasEncodedTagValue(Object r2, int r3) {
        /*
            r0 = 0
            boolean r1 = r2 instanceof byte[]
            if (r1 == 0) goto L_0x000e
            byte[] r2 = (byte[]) r2
            byte[] r2 = (byte[]) r2
            byte r1 = r2[r0]
            if (r1 != r3) goto L_0x000e
            r0 = 1
        L_0x000e:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.asn1.ASN1Object.hasEncodedTagValue(java.lang.Object, int):boolean");
    }
}
