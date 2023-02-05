package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class McElieceCCA2KeysToParams {
    public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key) throws InvalidKeyException {
        if (key instanceof BCMcElieceCCA2PublicKey) {
            return ((BCMcElieceCCA2PublicKey) key).getKeyParams();
        }
        throw new InvalidKeyException("can't identify McElieceCCA2 public key: " + key.getClass().getName());
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key) throws InvalidKeyException {
        if (key instanceof BCMcElieceCCA2PrivateKey) {
            return ((BCMcElieceCCA2PrivateKey) key).getKeyParams();
        }
        throw new InvalidKeyException("can't identify McElieceCCA2 private key.");
    }
}
