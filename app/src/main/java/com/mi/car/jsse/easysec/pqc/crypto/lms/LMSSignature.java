package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.util.Encodable;
import java.io.IOException;
import java.util.Arrays;

/* access modifiers changed from: package-private */
public class LMSSignature implements Encodable {
    private final LMOtsSignature otsSignature;
    private final LMSigParameters parameter;
    private final int q;
    private final byte[][] y;

    public LMSSignature(int q2, LMOtsSignature otsSignature2, LMSigParameters parameter2, byte[][] y2) {
        this.q = q2;
        this.otsSignature = otsSignature2;
        this.parameter = parameter2;
        this.y = y2;
    }

    /* JADX WARNING: Removed duplicated region for block: B:21:0x0064  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static LMSSignature getInstance(Object r10) throws IOException {
        /*
        // Method dump skipped, instructions count: 147
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.pqc.crypto.lms.LMSSignature.getInstance(java.lang.Object):com.mi.car.jsse.easysec.pqc.crypto.lms.LMSSignature");
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        LMSSignature that = (LMSSignature) o;
        if (this.q != that.q) {
            return false;
        }
        if (this.otsSignature != null) {
            if (!this.otsSignature.equals(that.otsSignature)) {
                return false;
            }
        } else if (that.otsSignature != null) {
            return false;
        }
        if (this.parameter != null) {
            if (!this.parameter.equals(that.parameter)) {
                return false;
            }
        } else if (that.parameter != null) {
            return false;
        }
        return Arrays.deepEquals(this.y, that.y);
    }

    public int hashCode() {
        int i;
        int i2 = 0;
        int i3 = this.q * 31;
        if (this.otsSignature != null) {
            i = this.otsSignature.hashCode();
        } else {
            i = 0;
        }
        int i4 = (i3 + i) * 31;
        if (this.parameter != null) {
            i2 = this.parameter.hashCode();
        }
        return ((i4 + i2) * 31) + Arrays.deepHashCode(this.y);
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable
    public byte[] getEncoded() throws IOException {
        return Composer.compose().u32str(this.q).bytes(this.otsSignature.getEncoded()).u32str(this.parameter.getType()).bytes(this.y).build();
    }

    public int getQ() {
        return this.q;
    }

    public LMOtsSignature getOtsSignature() {
        return this.otsSignature;
    }

    public LMSigParameters getParameter() {
        return this.parameter;
    }

    public byte[][] getY() {
        return this.y;
    }
}
