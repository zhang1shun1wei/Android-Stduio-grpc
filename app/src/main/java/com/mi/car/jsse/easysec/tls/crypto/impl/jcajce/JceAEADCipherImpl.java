package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.asn1.cms.GCMParameters;
import com.mi.car.jsse.easysec.jcajce.spec.AEADParameterSpec;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl;
import java.io.IOException;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class JceAEADCipherImpl implements TlsAEADCipherImpl {
    private static final boolean canDoAEAD = checkForAEAD();
    private final String algorithm;
    private final String algorithmParamsName;
    private final Cipher cipher;
    private final int cipherMode;
    private final JcaJceHelper helper;
    private SecretKey key;
    private final int keySize;

    private static boolean checkForAEAD() {
        return ((Boolean) AccessController.doPrivileged(new PrivilegedAction() {
            /* class com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.JceAEADCipherImpl.AnonymousClass1 */

            @Override // java.security.PrivilegedAction
            public Object run() {
                boolean z = true;
                try {
                    if (Cipher.class.getMethod("updateAAD", byte[].class) == null) {
                        z = false;
                    }
                    return Boolean.valueOf(z);
                } catch (Exception e) {
                    return Boolean.FALSE;
                }
            }
        })).booleanValue();
    }

    private static String getAlgParamsName(JcaJceHelper helper2, String cipherName) {
        try {
            String algName = cipherName.contains("CCM") ? "CCM" : "GCM";
            helper2.createAlgorithmParameters(algName);
            return algName;
        } catch (Exception e) {
            return null;
        }
    }

    public JceAEADCipherImpl(JcaJceHelper helper2, String cipherName, String algorithm2, int keySize2, boolean isEncrypting) throws GeneralSecurityException {
        this.helper = helper2;
        this.cipher = helper2.createCipher(cipherName);
        this.algorithm = algorithm2;
        this.keySize = keySize2;
        this.cipherMode = isEncrypting ? 1 : 2;
        this.algorithmParamsName = getAlgParamsName(helper2, cipherName);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public void setKey(byte[] key2, int keyOff, int keyLen) {
        if (this.keySize != keyLen) {
            throw new IllegalStateException();
        }
        this.key = new SecretKeySpec(key2, keyOff, keyLen, this.algorithm);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public void init(byte[] nonce, int macSize, byte[] additionalData) {
        try {
            if (!canDoAEAD || this.algorithmParamsName == null) {
                this.cipher.init(this.cipherMode, (Key) this.key, (AlgorithmParameterSpec) new AEADParameterSpec(nonce, macSize * 8, additionalData), (SecureRandom) null);
                return;
            }
            AlgorithmParameters algParams = this.helper.createAlgorithmParameters(this.algorithmParamsName);
            algParams.init(new GCMParameters(nonce, macSize).getEncoded());
            this.cipher.init(this.cipherMode, this.key, algParams, (SecureRandom) null);
            if (additionalData != null && additionalData.length > 0) {
                this.cipher.updateAAD(additionalData);
            }
        } catch (Exception e) {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public int getOutputSize(int inputLength) {
        return this.cipher.getOutputSize(inputLength);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl
    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException {
        try {
            return this.cipher.doFinal(input, inputOffset, inputLength, output, outputOffset);
        } catch (GeneralSecurityException e) {
            throw Exceptions.illegalStateException("", e);
        }
    }
}
