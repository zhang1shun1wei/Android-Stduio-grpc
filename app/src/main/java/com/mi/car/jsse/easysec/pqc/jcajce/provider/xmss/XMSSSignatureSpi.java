package com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.NullDigest;
import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSSigner;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.StateAwareSignature;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

public class XMSSSignatureSpi extends Signature implements StateAwareSignature {
    private Digest digest;
    private SecureRandom random;
    private XMSSSigner signer;
    private ASN1ObjectIdentifier treeDigest;

    protected XMSSSignatureSpi(String algorithm) {
        super(algorithm);
    }

    protected XMSSSignatureSpi(String sigName, Digest digest2, XMSSSigner signer2) {
        super(sigName);
        this.digest = digest2;
        this.signer = signer2;
    }

    /* access modifiers changed from: protected */
    @Override // java.security.SignatureSpi
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey instanceof BCXMSSPublicKey) {
            CipherParameters param = ((BCXMSSPublicKey) publicKey).getKeyParams();
            this.treeDigest = null;
            this.digest.reset();
            this.signer.init(false, param);
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
        if (privateKey instanceof BCXMSSPrivateKey) {
            CipherParameters param = ((BCXMSSPrivateKey) privateKey).getKeyParams();
            this.treeDigest = ((BCXMSSPrivateKey) privateKey).getTreeDigestOID();
            if (this.random != null) {
                param = new ParametersWithRandom(param, this.random);
            }
            this.digest.reset();
            this.signer.init(true, param);
            return;
        }
        throw new InvalidKeyException("unknown private key passed to XMSS");
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
                throw new SignatureException(e.getMessage(), e);
            }
            throw new SignatureException(e.toString(), e);
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

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.StateAwareSignature
    public boolean isSigningCapable() {
        return (this.treeDigest == null || this.signer.getUsagesRemaining() == 0) ? false : true;
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.StateAwareSignature
    public PrivateKey getUpdatedPrivateKey() {
        if (this.treeDigest == null) {
            throw new IllegalStateException("signature object not in a signing state");
        }
        PrivateKey rKey = new BCXMSSPrivateKey(this.treeDigest, (XMSSPrivateKeyParameters) this.signer.getUpdatedPrivateKey());
        this.treeDigest = null;
        return rKey;
    }

    public static class generic extends XMSSSignatureSpi {
        public generic() {
            super("XMSS", new NullDigest(), new XMSSSigner());
        }
    }

    public static class withSha256 extends XMSSSignatureSpi {
        public withSha256() {
            super("XMSS-SHA256", new NullDigest(), new XMSSSigner());
        }
    }

    public static class withShake128 extends XMSSSignatureSpi {
        public withShake128() {
            super("XMSS-SHAKE128", new NullDigest(), new XMSSSigner());
        }
    }

    public static class withSha512 extends XMSSSignatureSpi {
        public withSha512() {
            super("XMSS-SHA512", new NullDigest(), new XMSSSigner());
        }
    }

    public static class withShake256 extends XMSSSignatureSpi {
        public withShake256() {
            super("XMSS-SHAKE256", new NullDigest(), new XMSSSigner());
        }
    }

    public static class withSha256andPrehash extends XMSSSignatureSpi {
        public withSha256andPrehash() {
            super("SHA256withXMSS-SHA256", new SHA256Digest(), new XMSSSigner());
        }
    }

    public static class withShake128andPrehash extends XMSSSignatureSpi {
        public withShake128andPrehash() {
            super("SHAKE128withXMSSMT-SHAKE128", new SHAKEDigest(128), new XMSSSigner());
        }
    }

    public static class withSha512andPrehash extends XMSSSignatureSpi {
        public withSha512andPrehash() {
            super("SHA512withXMSS-SHA512", new SHA512Digest(), new XMSSSigner());
        }
    }

    public static class withShake256andPrehash extends XMSSSignatureSpi {
        public withShake256andPrehash() {
            super("SHAKE256withXMSS-SHAKE256", new SHAKEDigest(256), new XMSSSigner());
        }
    }
}
