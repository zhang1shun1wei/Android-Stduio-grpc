package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.util.Encodable;
import java.io.IOException;
import java.util.Arrays;

public class HSSSignature implements Encodable {
    private final int lMinus1;
    private final LMSSignature signature;
    private final LMSSignedPubKey[] signedPubKey;

    public HSSSignature(int lMinus12, LMSSignedPubKey[] signedPubKey2, LMSSignature signature2) {
        this.lMinus1 = lMinus12;
        this.signedPubKey = signedPubKey2;
        this.signature = signature2;
    }

    /* JADX WARNING: Removed duplicated region for block: B:27:0x0062  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static HSSSignature getInstance(Object r9, int r10) throws IOException {
        /*
        // Method dump skipped, instructions count: 145
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.pqc.crypto.lms.HSSSignature.getInstance(java.lang.Object, int):com.mi.car.jsse.easysec.pqc.crypto.lms.HSSSignature");
    }

    public int getlMinus1() {
        return this.lMinus1;
    }

    public LMSSignedPubKey[] getSignedPubKey() {
        return this.signedPubKey;
    }

    public LMSSignature getSignature() {
        return this.signature;
    }

    public boolean equals(Object o) {
        boolean z = true;
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        HSSSignature signature1 = (HSSSignature) o;
        if (!(this.lMinus1 == signature1.lMinus1 && this.signedPubKey.length == signature1.signedPubKey.length)) {
            return false;
        }
        for (int t = 0; t < this.signedPubKey.length; t++) {
            if (!this.signedPubKey[t].equals(signature1.signedPubKey[t])) {
                return false;
            }
        }
        if (this.signature != null) {
            z = this.signature.equals(signature1.signature);
        } else if (signature1.signature != null) {
            z = false;
        }
        return z;
    }

    public int hashCode() {
        return (((this.lMinus1 * 31) + Arrays.hashCode(this.signedPubKey)) * 31) + (this.signature != null ? this.signature.hashCode() : 0);
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable
    public byte[] getEncoded() throws IOException {
        Composer composer = Composer.compose();
        composer.u32str(this.lMinus1);
        if (this.signedPubKey != null) {
            for (LMSSignedPubKey sigPub : this.signedPubKey) {
                composer.bytes(sigPub);
            }
        }
        composer.bytes(this.signature);
        return composer.build();
    }
}
