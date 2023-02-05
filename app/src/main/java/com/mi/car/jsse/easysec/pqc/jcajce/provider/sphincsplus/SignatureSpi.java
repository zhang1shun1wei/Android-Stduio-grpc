package com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincsplus;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.NullDigest;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.sphincsplus.SPHINCSPlusSigner;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

public class SignatureSpi extends java.security.SignatureSpi {
    private final Digest digest;
    private final SPHINCSPlusSigner signer;

    protected SignatureSpi(Digest digest2, SPHINCSPlusSigner signer2) {
        this.digest = digest2;
        this.signer = signer2;
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey instanceof BCSPHINCSPlusPublicKey) {
            this.signer.init(false, ((BCSPHINCSPlusPublicKey) publicKey).getKeyParams());
            return;
        }
        throw new InvalidKeyException("unknown public key passed to SPHINCS-256");
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        this.appRandom = random;
        engineInitSign(privateKey);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey instanceof BCSPHINCSPlusPrivateKey) {
            CipherParameters param = ((BCSPHINCSPlusPrivateKey) privateKey).getKeyParams();
            if (this.appRandom != null) {
                this.signer.init(true, new ParametersWithRandom(param, this.appRandom));
            } else {
                this.signer.init(true, param);
            }
        } else {
            throw new InvalidKeyException("unknown private key passed to SPHINCS-256");
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineUpdate(byte b) throws SignatureException {
        this.digest.update(b);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        this.digest.update(b, off, len);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public byte[] engineSign() throws SignatureException {
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        try {
            return this.signer.generateSignature(hash);
        } catch (Exception e) {
            throw new SignatureException(e.toString());
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public boolean engineVerify(byte[] sigBytes) throws SignatureException {
        byte[] hash = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(hash, 0);
        return this.signer.verifySignature(hash, sigBytes);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineSetParameter(AlgorithmParameterSpec params) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public Object engineGetParameter(String param) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    public static class Direct extends SignatureSpi {
        public Direct() {
            super(new NullDigest(), new SPHINCSPlusSigner());
        }
    }
}
