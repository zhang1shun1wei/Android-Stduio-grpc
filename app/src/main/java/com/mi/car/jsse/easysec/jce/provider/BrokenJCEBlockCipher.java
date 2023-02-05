package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.engines.DESEngine;
import com.mi.car.jsse.easysec.crypto.engines.DESedeEngine;
import com.mi.car.jsse.easysec.crypto.engines.TwofishEngine;
import com.mi.car.jsse.easysec.crypto.modes.CBCBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.CFBBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.CTSBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.OFBBlockCipher;
import com.mi.car.jsse.easysec.crypto.paddings.PaddedBufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.params.RC2Parameters;
import com.mi.car.jsse.easysec.crypto.params.RC5Parameters;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BCPBEKey;
import com.mi.car.jsse.easysec.jce.provider.BrokenPBE;
import com.mi.car.jsse.easysec.util.Strings;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class BrokenJCEBlockCipher implements BrokenPBE {
    private Class[] availableSpecs = new Class[]{IvParameterSpec.class, PBEParameterSpec.class, RC2ParameterSpec.class, RC5ParameterSpec.class};
    private BufferedBlockCipher cipher;
    private ParametersWithIV ivParam;
    private int pbeType = 2;
    private int pbeHash = 1;
    private int pbeKeySize;
    private int pbeIvSize;
    private int ivLength = 0;
    private AlgorithmParameters engineParams = null;

    protected BrokenJCEBlockCipher(BlockCipher engine) {
        this.cipher = new PaddedBufferedBlockCipher(engine);
    }

    protected BrokenJCEBlockCipher(BlockCipher engine, int pbeType, int pbeHash, int pbeKeySize, int pbeIvSize) {
        this.cipher = new PaddedBufferedBlockCipher(engine);
        this.pbeType = pbeType;
        this.pbeHash = pbeHash;
        this.pbeKeySize = pbeKeySize;
        this.pbeIvSize = pbeIvSize;
    }

    protected int engineGetBlockSize() {
        return this.cipher.getBlockSize();
    }

    protected byte[] engineGetIV() {
        return this.ivParam != null ? this.ivParam.getIV() : null;
    }

    protected int engineGetKeySize(Key key) {
        return key.getEncoded().length;
    }

    protected int engineGetOutputSize(int inputLen) {
        return this.cipher.getOutputSize(inputLen);
    }

    protected AlgorithmParameters engineGetParameters() {
        if (this.engineParams == null && this.ivParam != null) {
            String name = this.cipher.getUnderlyingCipher().getAlgorithmName();
            if (name.indexOf(47) >= 0) {
                name = name.substring(0, name.indexOf(47));
            }

            try {
                this.engineParams = AlgorithmParameters.getInstance(name, "ES");
                this.engineParams.init(this.ivParam.getIV());
            } catch (Exception var3) {
                throw new RuntimeException(var3.toString());
            }
        }

        return this.engineParams;
    }

    protected void engineSetMode(String mode) {
        String modeName = Strings.toUpperCase(mode);
        if (modeName.equals("ECB")) {
            this.ivLength = 0;
            this.cipher = new PaddedBufferedBlockCipher(this.cipher.getUnderlyingCipher());
        } else if (modeName.equals("CBC")) {
            this.ivLength = this.cipher.getUnderlyingCipher().getBlockSize();
            this.cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(this.cipher.getUnderlyingCipher()));
        } else {
            int wordSize;
            if (modeName.startsWith("OFB")) {
                this.ivLength = this.cipher.getUnderlyingCipher().getBlockSize();
                if (modeName.length() != 3) {
                    wordSize = Integer.parseInt(modeName.substring(3));
                    this.cipher = new PaddedBufferedBlockCipher(new OFBBlockCipher(this.cipher.getUnderlyingCipher(), wordSize));
                } else {
                    this.cipher = new PaddedBufferedBlockCipher(new OFBBlockCipher(this.cipher.getUnderlyingCipher(), 8 * this.cipher.getBlockSize()));
                }
            } else {
                if (!modeName.startsWith("CFB")) {
                    throw new IllegalArgumentException("can't support mode " + mode);
                }

                this.ivLength = this.cipher.getUnderlyingCipher().getBlockSize();
                if (modeName.length() != 3) {
                    wordSize = Integer.parseInt(modeName.substring(3));
                    this.cipher = new PaddedBufferedBlockCipher(new CFBBlockCipher(this.cipher.getUnderlyingCipher(), wordSize));
                } else {
                    this.cipher = new PaddedBufferedBlockCipher(new CFBBlockCipher(this.cipher.getUnderlyingCipher(), 8 * this.cipher.getBlockSize()));
                }
            }
        }

    }

    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        String paddingName = Strings.toUpperCase(padding);
        if (paddingName.equals("NOPADDING")) {
            this.cipher = new BufferedBlockCipher(this.cipher.getUnderlyingCipher());
        } else if (!paddingName.equals("PKCS5PADDING") && !paddingName.equals("PKCS7PADDING") && !paddingName.equals("ISO10126PADDING")) {
            if (!paddingName.equals("WITHCTS")) {
                throw new NoSuchPaddingException("Padding " + padding + " unknown.");
            }

            this.cipher = new CTSBlockCipher(this.cipher.getUnderlyingCipher());
        } else {
            this.cipher = new PaddedBufferedBlockCipher(this.cipher.getUnderlyingCipher());
        }

    }

    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        Object param;
        if (key instanceof BCPBEKey) {
            param = Util.makePBEParameters((BCPBEKey)key, params, this.pbeType, this.pbeHash, this.cipher.getUnderlyingCipher().getAlgorithmName(), this.pbeKeySize, this.pbeIvSize);
            if (this.pbeIvSize != 0) {
                this.ivParam = (ParametersWithIV)param;
            }
        } else if (params == null) {
            param = new KeyParameter(key.getEncoded());
        } else if (params instanceof IvParameterSpec) {
            if (this.ivLength != 0) {
                param = new ParametersWithIV(new KeyParameter(key.getEncoded()), ((IvParameterSpec)params).getIV());
                this.ivParam = (ParametersWithIV)param;
            } else {
                param = new KeyParameter(key.getEncoded());
            }
        } else if (params instanceof RC2ParameterSpec) {
            RC2ParameterSpec rc2Param = (RC2ParameterSpec)params;
            param = new RC2Parameters(key.getEncoded(), ((RC2ParameterSpec)params).getEffectiveKeyBits());
            if (rc2Param.getIV() != null && this.ivLength != 0) {
                param = new ParametersWithIV((CipherParameters)param, rc2Param.getIV());
                this.ivParam = (ParametersWithIV)param;
            }
        } else {
            if (!(params instanceof RC5ParameterSpec)) {
                throw new InvalidAlgorithmParameterException("unknown parameter type.");
            }

            RC5ParameterSpec rc5Param = (RC5ParameterSpec)params;
            param = new RC5Parameters(key.getEncoded(), ((RC5ParameterSpec)params).getRounds());
            if (rc5Param.getWordSize() != 32) {
                throw new IllegalArgumentException("can only accept RC5 word size 32 (at the moment...)");
            }

            if (rc5Param.getIV() != null && this.ivLength != 0) {
                param = new ParametersWithIV((CipherParameters)param, rc5Param.getIV());
                this.ivParam = (ParametersWithIV)param;
            }
        }

        if (this.ivLength != 0 && !(param instanceof ParametersWithIV)) {
            if (random == null) {
                random = CryptoServicesRegistrar.getSecureRandom();
            }

            if (opmode != 1 && opmode != 3) {
                throw new InvalidAlgorithmParameterException("no IV set when one expected");
            }

            byte[] iv = new byte[this.ivLength];
            random.nextBytes(iv);
            param = new ParametersWithIV((CipherParameters)param, iv);
            this.ivParam = (ParametersWithIV)param;
        }

        switch(opmode) {
            case 1:
            case 3:
                this.cipher.init(true, (CipherParameters)param);
                break;
            case 2:
            case 4:
                this.cipher.init(false, (CipherParameters)param);
                break;
            default:
                throw new IllegalArgumentException("unknown opmode: " + opmode);
        }

    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec paramSpec = null;
        if (params != null) {
            int i = 0;

            while(i != this.availableSpecs.length) {
                try {
                    paramSpec = params.getParameterSpec(this.availableSpecs[i]);
                    break;
                } catch (Exception var8) {
                    ++i;
                }
            }

            if (paramSpec == null) {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + params.toString());
            }
        }

        this.engineParams = params;
        this.engineInit(opmode, key, paramSpec, random);
    }

    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            this.engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        } catch (InvalidAlgorithmParameterException var5) {
            throw new IllegalArgumentException(var5.getMessage());
        }
    }

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        int length = this.cipher.getUpdateOutputSize(inputLen);
        if (length > 0) {
            byte[] out = new byte[length];
            this.cipher.processBytes(input, inputOffset, inputLen, out, 0);
            return out;
        } else {
            this.cipher.processBytes(input, inputOffset, inputLen, (byte[])null, 0);
            return null;
        }
    }

    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        return this.cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);
    }

    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        int len = 0;
        byte[] tmp = new byte[this.engineGetOutputSize(inputLen)];
        if (inputLen != 0) {
            len = this.cipher.processBytes(input, inputOffset, inputLen, tmp, 0);
        }

        try {
            len += this.cipher.doFinal(tmp, len);
        } catch (DataLengthException var7) {
            throw new IllegalBlockSizeException(var7.getMessage());
        } catch (InvalidCipherTextException var8) {
            throw new BadPaddingException(var8.getMessage());
        }

        byte[] out = new byte[len];
        System.arraycopy(tmp, 0, out, 0, len);
        return out;
    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws IllegalBlockSizeException, BadPaddingException {
        int len = 0;
        if (inputLen != 0) {
            len = this.cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);
        }

        try {
            return len + this.cipher.doFinal(output, outputOffset + len);
        } catch (DataLengthException var8) {
            throw new IllegalBlockSizeException(var8.getMessage());
        } catch (InvalidCipherTextException var9) {
            throw new BadPaddingException(var9.getMessage());
        }
    }

    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Cannot wrap key, null encoding.");
        } else {
            try {
                return this.engineDoFinal(encoded, 0, encoded.length);
            } catch (BadPaddingException var4) {
                throw new IllegalBlockSizeException(var4.getMessage());
            }
        }
    }

    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) throws InvalidKeyException {
        Object var4 = null;

        byte[] encoded;
        try {
            encoded = this.engineDoFinal(wrappedKey, 0, wrappedKey.length);
        } catch (BadPaddingException var6) {
            throw new InvalidKeyException(var6.getMessage());
        } catch (IllegalBlockSizeException var7) {
            throw new InvalidKeyException(var7.getMessage());
        }

        if (wrappedKeyType == 3) {
            return new SecretKeySpec(encoded, wrappedKeyAlgorithm);
        } else {
            try {
                KeyFactory kf = KeyFactory.getInstance(wrappedKeyAlgorithm, "ES");
                if (wrappedKeyType == 1) {
                    return kf.generatePublic(new X509EncodedKeySpec(encoded));
                }

                if (wrappedKeyType == 2) {
                    return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
                }
            } catch (NoSuchProviderException var8) {
                throw new InvalidKeyException("Unknown key type " + var8.getMessage());
            } catch (NoSuchAlgorithmException var9) {
                throw new InvalidKeyException("Unknown key type " + var9.getMessage());
            } catch (InvalidKeySpecException var10) {
                throw new InvalidKeyException("Unknown key type " + var10.getMessage());
            }

            throw new InvalidKeyException("Unknown key type " + wrappedKeyType);
        }
    }

    public static class OldPBEWithSHAAndTwofish extends BrokenJCEBlockCipher {
        public OldPBEWithSHAAndTwofish() {
            super(new CBCBlockCipher(new TwofishEngine()), 3, 1, 256, 128);
        }
    }

    public static class BrokePBEWithSHAAndDES2Key extends BrokenJCEBlockCipher {
        public BrokePBEWithSHAAndDES2Key() {
            super(new CBCBlockCipher(new DESedeEngine()), 2, 1, 128, 64);
        }
    }

    public static class OldPBEWithSHAAndDES3Key extends BrokenJCEBlockCipher {
        public OldPBEWithSHAAndDES3Key() {
            super(new CBCBlockCipher(new DESedeEngine()), 3, 1, 192, 64);
        }
    }

    public static class BrokePBEWithSHAAndDES3Key extends BrokenJCEBlockCipher {
        public BrokePBEWithSHAAndDES3Key() {
            super(new CBCBlockCipher(new DESedeEngine()), 2, 1, 192, 64);
        }
    }

    public static class BrokePBEWithSHA1AndDES extends BrokenJCEBlockCipher {
        public BrokePBEWithSHA1AndDES() {
            super(new CBCBlockCipher(new DESEngine()), 0, 1, 64, 64);
        }
    }

    public static class BrokePBEWithMD5AndDES extends BrokenJCEBlockCipher {
        public BrokePBEWithMD5AndDES() {
            super(new CBCBlockCipher(new DESEngine()), 0, 0, 64, 64);
        }
    }
}