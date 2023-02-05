package com.mi.car.jsse.easysec.pqc.jcajce.provider.lms;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.NullDigest;
import com.mi.car.jsse.easysec.pqc.crypto.ExhaustedPrivateKeyException;
import com.mi.car.jsse.easysec.pqc.crypto.MessageSigner;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSContext;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSContextBasedSigner;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSContextBasedVerifier;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

public class LMSSignatureSpi extends Signature {
    private Digest digest;
    private LMSContextBasedSigner lmOtsSigner;
    private LMSContextBasedVerifier lmOtsVerifier;
    private SecureRandom random;
    private MessageSigner signer;

    protected LMSSignatureSpi(String algorithm) {
        super(algorithm);
    }

    protected LMSSignatureSpi(String sigName, Digest digest2) {
        super(sigName);
        this.digest = digest2;
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey instanceof BCLMSPublicKey) {
            this.digest = new NullDigest();
            this.digest.reset();
            this.lmOtsVerifier = (LMSContextBasedVerifier) ((BCLMSPublicKey) publicKey).getKeyParams();
            return;
        }
        throw new InvalidKeyException("unknown public key passed to XMSS");
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineInitSign(PrivateKey privateKey, SecureRandom random2) throws InvalidKeyException {
        this.random = random2;
        engineInitSign(privateKey);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey instanceof BCLMSPrivateKey) {
            this.lmOtsSigner = (LMSContextBasedSigner) ((BCLMSPrivateKey) privateKey).getKeyParams();
            if (this.lmOtsSigner.getUsagesRemaining() == 0) {
                throw new InvalidKeyException("private key exhausted");
            }
            this.digest = null;
            return;
        }
        throw new InvalidKeyException("unknown private key passed to LMS");
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineUpdate(byte b) throws SignatureException {
        if (this.digest == null) {
            this.digest = getSigner();
        }
        this.digest.update(b);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (this.digest == null) {
            this.digest = getSigner();
        }
        this.digest.update(b, off, len);
    }

    private Digest getSigner() throws SignatureException {
        try {
            return this.lmOtsSigner.generateLMSContext();
        } catch (ExhaustedPrivateKeyException e) {
            throw new SignatureException(e.getMessage(), e);
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public byte[] engineSign() throws SignatureException {
        if (this.digest == null) {
            this.digest = getSigner();
        }
        try {
            byte[] sig = this.lmOtsSigner.generateSignature((LMSContext) this.digest);
            this.digest = null;
            return sig;
        } catch (Exception e) {
            if (e instanceof IllegalStateException) {
                throw new SignatureException(e.getMessage(), e);
            }
            throw new SignatureException(e.toString(), e);
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public boolean engineVerify(byte[] sigBytes) throws SignatureException {
        LMSContext context = this.lmOtsVerifier.generateLMSContext(sigBytes);
        byte[] hash = DigestUtil.getDigestResult(this.digest);
        context.update(hash, 0, hash.length);
        return this.lmOtsVerifier.verify(context);
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

    public static class generic extends LMSSignatureSpi {
        public generic() {
            super("LMS", new NullDigest());
        }
    }
}
