package com.mi.car.jsse.easysec.pqc.crypto.lms;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public class LMSPublicKeyParameters extends LMSKeyParameters implements LMSContextBasedVerifier {
    private final byte[] I;
    private final byte[] T1;
    private final LMOtsParameters lmOtsType;
    private final LMSigParameters parameterSet;

    public LMSPublicKeyParameters(LMSigParameters parameterSet2, LMOtsParameters lmOtsType2, byte[] T12, byte[] I2) {
        super(false);
        this.parameterSet = parameterSet2;
        this.lmOtsType = lmOtsType2;
        this.I = Arrays.clone(I2);
        this.T1 = Arrays.clone(T12);
    }

    /* JADX WARNING: Removed duplicated region for block: B:17:0x005c  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static LMSPublicKeyParameters getInstance(Object r10) throws IOException {
        /*
        // Method dump skipped, instructions count: 139
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.pqc.crypto.lms.LMSPublicKeyParameters.getInstance(java.lang.Object):com.mi.car.jsse.easysec.pqc.crypto.lms.LMSPublicKeyParameters");
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable, com.mi.car.jsse.easysec.pqc.crypto.lms.LMSKeyParameters
    public byte[] getEncoded() throws IOException {
        return toByteArray();
    }

    public LMSigParameters getSigParameters() {
        return this.parameterSet;
    }

    public LMOtsParameters getOtsParameters() {
        return this.lmOtsType;
    }

    public LMSParameters getLMSParameters() {
        return new LMSParameters(getSigParameters(), getOtsParameters());
    }

    public byte[] getT1() {
        return Arrays.clone(this.T1);
    }

    /* access modifiers changed from: package-private */
    public boolean matchesT1(byte[] sig) {
        return Arrays.constantTimeAreEqual(this.T1, sig);
    }

    public byte[] getI() {
        return Arrays.clone(this.I);
    }

    /* access modifiers changed from: package-private */
    public byte[] refI() {
        return this.I;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        LMSPublicKeyParameters publicKey = (LMSPublicKeyParameters) o;
        if (!this.parameterSet.equals(publicKey.parameterSet) || !this.lmOtsType.equals(publicKey.lmOtsType) || !Arrays.areEqual(this.I, publicKey.I)) {
            return false;
        }
        return Arrays.areEqual(this.T1, publicKey.T1);
    }

    public int hashCode() {
        return (((((this.parameterSet.hashCode() * 31) + this.lmOtsType.hashCode()) * 31) + Arrays.hashCode(this.I)) * 31) + Arrays.hashCode(this.T1);
    }

    /* access modifiers changed from: package-private */
    public byte[] toByteArray() {
        return Composer.compose().u32str(this.parameterSet.getType()).u32str(this.lmOtsType.getType()).bytes(this.I).bytes(this.T1).build();
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.lms.LMSContextBasedVerifier
    public LMSContext generateLMSContext(byte[] signature) {
        try {
            return generateOtsContext(LMSSignature.getInstance(signature));
        } catch (IOException e) {
            throw new IllegalStateException("cannot parse signature: " + e.getMessage());
        }
    }

    /* access modifiers changed from: package-private */
    public LMSContext generateOtsContext(LMSSignature S) {
        int ots_typecode = getOtsParameters().getType();
        if (S.getOtsSignature().getType().getType() == ots_typecode) {
            return new LMOtsPublicKey(LMOtsParameters.getParametersForType(ots_typecode), this.I, S.getQ(), null).createOtsContext(S);
        }
        throw new IllegalArgumentException("ots type from lsm signature does not match ots signature type from embedded ots signature");
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.lms.LMSContextBasedVerifier
    public boolean verify(LMSContext context) {
        return LMS.verifySignature(this, context);
    }
}
