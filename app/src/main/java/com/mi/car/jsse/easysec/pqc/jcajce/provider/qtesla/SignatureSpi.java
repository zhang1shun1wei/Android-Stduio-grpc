package com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.NullDigest;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLASecurityCategory;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLASigner;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

public class SignatureSpi extends Signature {
    private Digest digest;
    private SecureRandom random;
    private QTESLASigner signer;

    protected SignatureSpi(String algorithm) {
        super(algorithm);
    }

    protected SignatureSpi(String sigName, Digest digest2, QTESLASigner signer2) {
        super(sigName);
        this.digest = digest2;
        this.signer = signer2;
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey instanceof BCqTESLAPublicKey) {
            CipherParameters param = ((BCqTESLAPublicKey) publicKey).getKeyParams();
            this.digest.reset();
            this.signer.init(false, param);
            return;
        }
        throw new InvalidKeyException("unknown public key passed to qTESLA");
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
        if (privateKey instanceof BCqTESLAPrivateKey) {
            CipherParameters param = ((BCqTESLAPrivateKey) privateKey).getKeyParams();
            if (this.random != null) {
                param = new ParametersWithRandom(param, this.random);
            }
            this.signer.init(true, param);
            return;
        }
        throw new InvalidKeyException("unknown private key passed to qTESLA");
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
        try {
            return this.signer.generateSignature(DigestUtil.getDigestResult(this.digest));
        } catch (Exception e) {
            if (e instanceof IllegalStateException) {
                throw new SignatureException(e.getMessage());
            }
            throw new SignatureException(e.toString());
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return this.signer.verifySignature(DigestUtil.getDigestResult(this.digest), sigBytes);
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

    public static class qTESLA extends SignatureSpi {
        public qTESLA() {
            super("qTESLA", new NullDigest(), new QTESLASigner());
        }
    }

    public static class PI extends SignatureSpi {
        public PI() {
            super(QTESLASecurityCategory.getName(5), new NullDigest(), new QTESLASigner());
        }
    }

    public static class PIII extends SignatureSpi {
        public PIII() {
            super(QTESLASecurityCategory.getName(6), new NullDigest(), new QTESLASigner());
        }
    }
}
