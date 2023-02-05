package com.mi.car.jsse.easysec.pqc.jcajce.provider.saber;

import com.mi.car.jsse.easysec.crypto.SecretWithEncapsulation;
import com.mi.car.jsse.easysec.jcajce.SecretKeyWithEncapsulation;
import com.mi.car.jsse.easysec.jcajce.spec.KEMExtractSpec;
import com.mi.car.jsse.easysec.jcajce.spec.KEMGenerateSpec;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERKEMExtractor;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERKEMGenerator;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

public class SABERKeyGeneratorSpi extends KeyGeneratorSpi {
    private KEMExtractSpec extSpec;
    private KEMGenerateSpec genSpec;
    private SecureRandom random;

    /* access modifiers changed from: protected */
    public void engineInit(SecureRandom secureRandom) {
        throw new UnsupportedOperationException("Operation not supported");
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.KeyGeneratorSpi
    public void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        this.random = secureRandom;
        if (algorithmParameterSpec instanceof KEMGenerateSpec) {
            this.genSpec = (KEMGenerateSpec) algorithmParameterSpec;
            this.extSpec = null;
        } else if (algorithmParameterSpec instanceof KEMExtractSpec) {
            this.genSpec = null;
            this.extSpec = (KEMExtractSpec) algorithmParameterSpec;
        } else {
            throw new InvalidAlgorithmParameterException("unknown spec");
        }
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.KeyGeneratorSpi
    public void engineInit(int i, SecureRandom secureRandom) {
        throw new UnsupportedOperationException("Operation not supported");
    }

    /* access modifiers changed from: protected */
    public SecretKey engineGenerateKey() {
        if (this.genSpec != null) {
            SecretWithEncapsulation secEnc = new SABERKEMGenerator(this.random).generateEncapsulated(((BCSABERPublicKey) this.genSpec.getPublicKey()).getKeyParams());
            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(secEnc.getSecret(), this.genSpec.getKeyAlgorithmName()), secEnc.getEncapsulation());
            try {
                secEnc.destroy();
                return rv;
            } catch (DestroyFailedException e) {
                throw new IllegalStateException("key cleanup failed");
            }
        } else {
            SABERKEMExtractor kemExt = new SABERKEMExtractor(((BCSABERPrivateKey) this.extSpec.getPrivateKey()).getKeyParams());
            byte[] encapsulation = this.extSpec.getEncapsulation();
            byte[] secret = kemExt.extractSecret(encapsulation);
            SecretKey rv2 = new SecretKeyWithEncapsulation(new SecretKeySpec(secret, this.extSpec.getKeyAlgorithmName()), encapsulation);
            Arrays.clear(secret);
            return rv2;
        }
    }
}
