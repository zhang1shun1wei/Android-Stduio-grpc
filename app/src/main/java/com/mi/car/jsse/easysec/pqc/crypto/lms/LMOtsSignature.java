package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.util.Encodable;
import java.io.IOException;
import java.util.Arrays;

/* access modifiers changed from: package-private */
public class LMOtsSignature implements Encodable {
    private final byte[] C;
    private final LMOtsParameters type;
    private final byte[] y;

    public LMOtsSignature(LMOtsParameters type2, byte[] c, byte[] y2) {
        this.type = type2;
        this.C = c;
        this.y = y2;
    }

    /* JADX WARNING: Removed duplicated region for block: B:17:0x0058  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static LMOtsSignature getInstance(Object r8) throws IOException {
        /*
        // Method dump skipped, instructions count: 135
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.pqc.crypto.lms.LMOtsSignature.getInstance(java.lang.Object):com.mi.car.jsse.easysec.pqc.crypto.lms.LMOtsSignature");
    }

    public LMOtsParameters getType() {
        return this.type;
    }

    public byte[] getC() {
        return this.C;
    }

    public byte[] getY() {
        return this.y;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        LMOtsSignature that = (LMOtsSignature) o;
        if (this.type != null) {
            if (!this.type.equals(that.type)) {
                return false;
            }
        } else if (that.type != null) {
            return false;
        }
        if (Arrays.equals(this.C, that.C)) {
            return Arrays.equals(this.y, that.y);
        }
        return false;
    }

    public int hashCode() {
        return ((((this.type != null ? this.type.hashCode() : 0) * 31) + Arrays.hashCode(this.C)) * 31) + Arrays.hashCode(this.y);
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable
    public byte[] getEncoded() throws IOException {
        return Composer.compose().u32str(this.type.getType()).bytes(this.C).bytes(this.y).build();
    }
}
