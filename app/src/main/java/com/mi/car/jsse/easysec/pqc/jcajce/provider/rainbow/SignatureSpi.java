package com.mi.car.jsse.easysec.pqc.jcajce.provider.rainbow;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA224Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA384Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.RainbowSigner;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

public class SignatureSpi extends java.security.SignatureSpi {
    private Digest digest;
    private SecureRandom random;
    private RainbowSigner signer;

    protected SignatureSpi(Digest digest2, RainbowSigner signer2) {
        this.digest = digest2;
        this.signer = signer2;
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        CipherParameters param = RainbowKeysToParams.generatePublicKeyParameter(publicKey);
        this.digest.reset();
        this.signer.init(false, param);
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
        CipherParameters param = RainbowKeysToParams.generatePrivateKeyParameter(privateKey);
        if (this.random != null) {
            param = new ParametersWithRandom(param, this.random);
        }
        this.digest.reset();
        this.signer.init(true, param);
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

    public static class withSha224 extends SignatureSpi {
        public withSha224() {
            super(new SHA224Digest(), new RainbowSigner());
        }
    }

    public static class withSha256 extends SignatureSpi {
        public withSha256() {
            super(new SHA256Digest(), new RainbowSigner());
        }
    }

    public static class withSha384 extends SignatureSpi {
        public withSha384() {
            super(new SHA384Digest(), new RainbowSigner());
        }
    }

    public static class withSha512 extends SignatureSpi {
        public withSha512() {
            super(new SHA512Digest(), new RainbowSigner());
        }
    }
}
