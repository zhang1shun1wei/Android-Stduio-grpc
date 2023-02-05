package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.util.Encodable;
import java.io.IOException;

/* access modifiers changed from: package-private */
public class LMSSignedPubKey implements Encodable {
    private final LMSPublicKeyParameters publicKey;
    private final LMSSignature signature;

    public LMSSignedPubKey(LMSSignature signature2, LMSPublicKeyParameters publicKey2) {
        this.signature = signature2;
        this.publicKey = publicKey2;
    }

    public LMSSignature getSignature() {
        return this.signature;
    }

    public LMSPublicKeyParameters getPublicKey() {
        return this.publicKey;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        LMSSignedPubKey that = (LMSSignedPubKey) o;
        if (this.signature == null ? that.signature != null : !this.signature.equals(that.signature)) {
            return false;
        }
        if (this.publicKey != null) {
            return this.publicKey.equals(that.publicKey);
        }
        return that.publicKey == null;
    }

    public int hashCode() {
        int result;
        int i = 0;
        if (this.signature != null) {
            result = this.signature.hashCode();
        } else {
            result = 0;
        }
        int i2 = result * 31;
        if (this.publicKey != null) {
            i = this.publicKey.hashCode();
        }
        return i2 + i;
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable
    public byte[] getEncoded() throws IOException {
        return Composer.compose().bytes(this.signature.getEncoded()).bytes(this.publicKey.getEncoded()).build();
    }
}
