package com.mi.car.jsse.easysec.pqc.crypto.lms;

import java.io.IOException;

public class HSSPublicKeyParameters extends LMSKeyParameters implements LMSContextBasedVerifier {
    private final int l;
    private final LMSPublicKeyParameters lmsPublicKey;

    public HSSPublicKeyParameters(int l2, LMSPublicKeyParameters lmsPublicKey2) {
        super(false);
        this.l = l2;
        this.lmsPublicKey = lmsPublicKey2;
    }

    /* JADX WARNING: Removed duplicated region for block: B:17:0x003c  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static HSSPublicKeyParameters getInstance(Object r7) throws IOException {
        /*
        // Method dump skipped, instructions count: 107
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.pqc.crypto.lms.HSSPublicKeyParameters.getInstance(java.lang.Object):com.mi.car.jsse.easysec.pqc.crypto.lms.HSSPublicKeyParameters");
    }

    public int getL() {
        return this.l;
    }

    public LMSPublicKeyParameters getLMSPublicKey() {
        return this.lmsPublicKey;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        HSSPublicKeyParameters publicKey = (HSSPublicKeyParameters) o;
        if (this.l == publicKey.l) {
            return this.lmsPublicKey.equals(publicKey.lmsPublicKey);
        }
        return false;
    }

    public int hashCode() {
        return (this.l * 31) + this.lmsPublicKey.hashCode();
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable, com.mi.car.jsse.easysec.pqc.crypto.lms.LMSKeyParameters
    public byte[] getEncoded() throws IOException {
        return Composer.compose().u32str(this.l).bytes(this.lmsPublicKey.getEncoded()).build();
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.lms.LMSContextBasedVerifier
    public LMSContext generateLMSContext(byte[] sigEnc) {
        try {
            HSSSignature signature = HSSSignature.getInstance(sigEnc, getL());
            LMSSignedPubKey[] signedPubKeys = signature.getSignedPubKey();
            return signedPubKeys[signedPubKeys.length - 1].getPublicKey().generateOtsContext(signature.getSignature()).withSignedPublicKeys(signedPubKeys);
        } catch (IOException e) {
            throw new IllegalStateException("cannot parse signature: " + e.getMessage());
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.lms.LMSContextBasedVerifier
    public boolean verify(LMSContext context) {
        boolean z = false;
        boolean failed = false;
        LMSSignedPubKey[] sigKeys = context.getSignedPubKeys();
        if (sigKeys.length != getL() - 1) {
            return false;
        }
        LMSPublicKeyParameters key = getLMSPublicKey();
        for (int i = 0; i < sigKeys.length; i++) {
            if (!LMS.verifySignature(key, sigKeys[i].getSignature(), sigKeys[i].getPublicKey().toByteArray())) {
                failed = true;
            }
            key = sigKeys[i].getPublicKey();
        }
        if (!failed) {
            z = true;
        }
        return z & key.verify(context);
    }
}
