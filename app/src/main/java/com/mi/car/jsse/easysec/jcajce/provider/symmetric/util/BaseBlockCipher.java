//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.jcajce.provider.symmetric.util;

import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.engines.DSTU7624Engine;
import com.mi.car.jsse.easysec.crypto.fpe.FPEEngine;
import com.mi.car.jsse.easysec.crypto.fpe.FPEFF1Engine;
import com.mi.car.jsse.easysec.crypto.fpe.FPEFF3_1Engine;
import com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.AEADCipher;
import com.mi.car.jsse.easysec.crypto.modes.CBCBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.CCMBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.CFBBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.CTSBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.EAXBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.GCFBBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.GCMBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.GCMSIVBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.GOFBBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.KCCMBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.KCTRBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.KGCMBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.OCBBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.OFBBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.OpenPGPCFBBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.PGPCFBBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.SICBlockCipher;
import com.mi.car.jsse.easysec.crypto.paddings.BlockCipherPadding;
import com.mi.car.jsse.easysec.crypto.paddings.ISO10126d2Padding;
import com.mi.car.jsse.easysec.crypto.paddings.ISO7816d4Padding;
import com.mi.car.jsse.easysec.crypto.paddings.PaddedBufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.paddings.TBCPadding;
import com.mi.car.jsse.easysec.crypto.paddings.X923Padding;
import com.mi.car.jsse.easysec.crypto.paddings.ZeroBytePadding;
import com.mi.car.jsse.easysec.crypto.params.AEADParameters;
import com.mi.car.jsse.easysec.crypto.params.FPEParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithSBox;
import com.mi.car.jsse.easysec.crypto.params.RC2Parameters;
import com.mi.car.jsse.easysec.crypto.params.RC5Parameters;
import com.mi.car.jsse.easysec.internal.asn1.cms.GCMParameters;
import com.mi.car.jsse.easysec.jcajce.PBKDF1Key;
import com.mi.car.jsse.easysec.jcajce.PBKDF1KeyWithParameters;
import com.mi.car.jsse.easysec.jcajce.PKCS12Key;
import com.mi.car.jsse.easysec.jcajce.PKCS12KeyWithParameters;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseWrapCipher.ErasableOutputStream;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseWrapCipher.InvalidKeyOrParametersException;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.PBE.Util;
import com.mi.car.jsse.easysec.jcajce.spec.AEADParameterSpec;
import com.mi.car.jsse.easysec.jcajce.spec.FPEParameterSpec;
import com.mi.car.jsse.easysec.jcajce.spec.GOST28147ParameterSpec;
import com.mi.car.jsse.easysec.jcajce.spec.RepeatedSecretKeySpec;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;

public class BaseBlockCipher extends BaseWrapCipher implements PBE {
    private static final int BUF_SIZE = 512;
    private static final Class gcmSpecClass = ClassUtil.loadClass(BaseBlockCipher.class, "javax.crypto.spec.GCMParameterSpec");
    private Class[] availableSpecs;
    private BlockCipher baseEngine;
    private BlockCipherProvider engineProvider;
    private BaseBlockCipher.GenericBlockCipher cipher;
    private ParametersWithIV ivParam;
    private AEADParameters aeadParams;
    private int keySizeInBits;
    private int scheme;
    private int digest;
    private int ivLength;
    private boolean padded;
    private boolean fixedIv;
    private PBEParameterSpec pbeSpec;
    private String pbeAlgorithm;
    private String modeName;

    protected BaseBlockCipher(BlockCipher engine) {
        this.availableSpecs = new Class[]{RC2ParameterSpec.class, RC5ParameterSpec.class, gcmSpecClass, GOST28147ParameterSpec.class, IvParameterSpec.class, PBEParameterSpec.class};
        this.scheme = -1;
        this.ivLength = 0;
        this.fixedIv = true;
        this.pbeSpec = null;
        this.pbeAlgorithm = null;
        this.modeName = null;
        this.baseEngine = engine;
        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(engine);
    }

    protected BaseBlockCipher(BlockCipher engine, int scheme, int digest, int keySizeInBits, int ivLength) {
        this.availableSpecs = new Class[]{RC2ParameterSpec.class, RC5ParameterSpec.class, gcmSpecClass, GOST28147ParameterSpec.class, IvParameterSpec.class, PBEParameterSpec.class};
        this.scheme = -1;
        this.ivLength = 0;
        this.fixedIv = true;
        this.pbeSpec = null;
        this.pbeAlgorithm = null;
        this.modeName = null;
        this.baseEngine = engine;
        this.scheme = scheme;
        this.digest = digest;
        this.keySizeInBits = keySizeInBits;
        this.ivLength = ivLength;
        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(engine);
    }

    protected BaseBlockCipher(BlockCipherProvider provider) {
        this.availableSpecs = new Class[]{RC2ParameterSpec.class, RC5ParameterSpec.class, gcmSpecClass, GOST28147ParameterSpec.class, IvParameterSpec.class, PBEParameterSpec.class};
        this.scheme = -1;
        this.ivLength = 0;
        this.fixedIv = true;
        this.pbeSpec = null;
        this.pbeAlgorithm = null;
        this.modeName = null;
        this.baseEngine = provider.get();
        this.engineProvider = provider;
        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(provider.get());
    }

    protected BaseBlockCipher(AEADBlockCipher engine) {
        this.availableSpecs = new Class[]{RC2ParameterSpec.class, RC5ParameterSpec.class, gcmSpecClass, GOST28147ParameterSpec.class, IvParameterSpec.class, PBEParameterSpec.class};
        this.scheme = -1;
        this.ivLength = 0;
        this.fixedIv = true;
        this.pbeSpec = null;
        this.pbeAlgorithm = null;
        this.modeName = null;
        this.baseEngine = engine.getUnderlyingCipher();
        if (engine.getAlgorithmName().indexOf("GCM") >= 0) {
            this.ivLength = 12;
        } else {
            this.ivLength = this.baseEngine.getBlockSize();
        }

        this.cipher = new BaseBlockCipher.AEADGenericBlockCipher(engine);
    }

    protected BaseBlockCipher(AEADCipher engine, boolean fixedIv, int ivLength) {
        this.availableSpecs = new Class[]{RC2ParameterSpec.class, RC5ParameterSpec.class, gcmSpecClass, GOST28147ParameterSpec.class, IvParameterSpec.class, PBEParameterSpec.class};
        this.scheme = -1;
        this.ivLength = 0;
        this.fixedIv = true;
        this.pbeSpec = null;
        this.pbeAlgorithm = null;
        this.modeName = null;
        this.baseEngine = null;
        this.fixedIv = fixedIv;
        this.ivLength = ivLength;
        this.cipher = new BaseBlockCipher.AEADGenericBlockCipher(engine);
    }

    protected BaseBlockCipher(AEADBlockCipher engine, boolean fixedIv, int ivLength) {
        this.availableSpecs = new Class[]{RC2ParameterSpec.class, RC5ParameterSpec.class, gcmSpecClass, GOST28147ParameterSpec.class, IvParameterSpec.class, PBEParameterSpec.class};
        this.scheme = -1;
        this.ivLength = 0;
        this.fixedIv = true;
        this.pbeSpec = null;
        this.pbeAlgorithm = null;
        this.modeName = null;
        this.baseEngine = engine.getUnderlyingCipher();
        this.fixedIv = fixedIv;
        this.ivLength = ivLength;
        this.cipher = new BaseBlockCipher.AEADGenericBlockCipher(engine);
    }

    protected BaseBlockCipher(BlockCipher engine, int ivLength) {
        this(engine, true, ivLength);
    }

    protected BaseBlockCipher(BlockCipher engine, boolean fixedIv, int ivLength) {
        this.availableSpecs = new Class[]{RC2ParameterSpec.class, RC5ParameterSpec.class, gcmSpecClass, GOST28147ParameterSpec.class, IvParameterSpec.class, PBEParameterSpec.class};
        this.scheme = -1;
        this.ivLength = 0;
        this.fixedIv = true;
        this.pbeSpec = null;
        this.pbeAlgorithm = null;
        this.modeName = null;
        this.baseEngine = engine;
        this.fixedIv = fixedIv;
        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(engine);
        this.ivLength = ivLength / 8;
    }

    protected BaseBlockCipher(BufferedBlockCipher engine, int ivLength) {
        this(engine, true, ivLength);
    }

    protected BaseBlockCipher(BufferedBlockCipher engine, boolean fixedIv, int ivLength) {
        this.availableSpecs = new Class[]{RC2ParameterSpec.class, RC5ParameterSpec.class, gcmSpecClass, GOST28147ParameterSpec.class, IvParameterSpec.class, PBEParameterSpec.class};
        this.scheme = -1;
        this.ivLength = 0;
        this.fixedIv = true;
        this.pbeSpec = null;
        this.pbeAlgorithm = null;
        this.modeName = null;
        this.baseEngine = engine.getUnderlyingCipher();
        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(engine);
        this.fixedIv = fixedIv;
        this.ivLength = ivLength / 8;
    }

    protected int engineGetBlockSize() {
        return this.baseEngine == null ? -1 : this.baseEngine.getBlockSize();
    }

    protected byte[] engineGetIV() {
        if (this.aeadParams != null) {
            return this.aeadParams.getNonce();
        } else {
            return this.ivParam != null ? this.ivParam.getIV() : null;
        }
    }

    protected int engineGetKeySize(Key key) {
        return key.getEncoded().length * 8;
    }

    protected int engineGetOutputSize(int inputLen) {
        return this.cipher.getOutputSize(inputLen);
    }

    protected AlgorithmParameters engineGetParameters() {
        if (this.engineParams == null) {
            if (this.pbeSpec != null) {
                try {
                    this.engineParams = this.createParametersInstance(this.pbeAlgorithm);
                    this.engineParams.init(this.pbeSpec);
                } catch (Exception var6) {
                    return null;
                }
            } else if (this.aeadParams != null) {
                if (this.baseEngine == null) {
                    try {
                        this.engineParams = this.createParametersInstance(PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305.getId());
                        this.engineParams.init((new DEROctetString(this.aeadParams.getNonce())).getEncoded());
                    } catch (Exception var5) {
                        throw new RuntimeException(var5.toString());
                    }
                } else {
                    try {
                        this.engineParams = this.createParametersInstance("GCM");
                        this.engineParams.init((new GCMParameters(this.aeadParams.getNonce(), this.aeadParams.getMacSize() / 8)).getEncoded());
                    } catch (Exception var4) {
                        throw new RuntimeException(var4.toString());
                    }
                }
            } else if (this.ivParam != null) {
                String name = this.cipher.getUnderlyingCipher().getAlgorithmName();
                if (name.indexOf(47) >= 0) {
                    name = name.substring(0, name.indexOf(47));
                }

                try {
                    this.engineParams = this.createParametersInstance(name);
                    this.engineParams.init(new IvParameterSpec(this.ivParam.getIV()));
                } catch (Exception var3) {
                    throw new RuntimeException(var3.toString());
                }
            }
        }

        return this.engineParams;
    }

    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (this.baseEngine == null) {
            throw new NoSuchAlgorithmException("no mode supported for this algorithm");
        } else {
            this.modeName = Strings.toUpperCase(mode);
            if (this.modeName.equals("ECB")) {
                this.ivLength = 0;
                this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(this.baseEngine);
            } else if (this.modeName.equals("CBC")) {
                this.ivLength = this.baseEngine.getBlockSize();
                this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new CBCBlockCipher(this.baseEngine));
            } else {
                int wordSize;
                if (this.modeName.startsWith("OFB")) {
                    this.ivLength = this.baseEngine.getBlockSize();
                    if (this.modeName.length() != 3) {
                        wordSize = Integer.parseInt(this.modeName.substring(3));
                        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new OFBBlockCipher(this.baseEngine, wordSize));
                    } else {
                        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new OFBBlockCipher(this.baseEngine, 8 * this.baseEngine.getBlockSize()));
                    }
                } else if (this.modeName.startsWith("CFB")) {
                    this.ivLength = this.baseEngine.getBlockSize();
                    if (this.modeName.length() != 3) {
                        wordSize = Integer.parseInt(this.modeName.substring(3));
                        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new CFBBlockCipher(this.baseEngine, wordSize));
                    } else {
                        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new CFBBlockCipher(this.baseEngine, 8 * this.baseEngine.getBlockSize()));
                    }
                } else if (this.modeName.startsWith("PGPCFB")) {
                    boolean inlineIV = this.modeName.equals("PGPCFBWITHIV");
                    if (!inlineIV && this.modeName.length() != 6) {
                        throw new NoSuchAlgorithmException("no mode support for " + this.modeName);
                    }

                    this.ivLength = this.baseEngine.getBlockSize();
                    this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new PGPCFBBlockCipher(this.baseEngine, inlineIV));
                } else if (this.modeName.equals("OPENPGPCFB")) {
                    this.ivLength = 0;
                    this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new OpenPGPCFBBlockCipher(this.baseEngine));
                } else if (this.modeName.equals("FF1")) {
                    this.ivLength = 0;
                    this.cipher = new BaseBlockCipher.BufferedFPEBlockCipher(new FPEFF1Engine(this.baseEngine));
                } else if (this.modeName.equals("FF3-1")) {
                    this.ivLength = 0;
                    this.cipher = new BaseBlockCipher.BufferedFPEBlockCipher(new FPEFF3_1Engine(this.baseEngine));
                } else if (this.modeName.equals("SIC")) {
                    this.ivLength = this.baseEngine.getBlockSize();
                    if (this.ivLength < 16) {
                        throw new IllegalArgumentException("Warning: SIC-Mode can become a twotime-pad if the blocksize of the cipher is too small. Use a cipher with a block size of at least 128 bits (e.g. AES)");
                    }

                    this.fixedIv = false;
                    this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new BufferedBlockCipher(new SICBlockCipher(this.baseEngine)));
                } else if (this.modeName.equals("CTR")) {
                    this.ivLength = this.baseEngine.getBlockSize();
                    this.fixedIv = false;
                    if (this.baseEngine instanceof DSTU7624Engine) {
                        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new BufferedBlockCipher(new KCTRBlockCipher(this.baseEngine)));
                    } else {
                        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new BufferedBlockCipher(new SICBlockCipher(this.baseEngine)));
                    }
                } else if (this.modeName.equals("GOFB")) {
                    this.ivLength = this.baseEngine.getBlockSize();
                    this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new BufferedBlockCipher(new GOFBBlockCipher(this.baseEngine)));
                } else if (this.modeName.equals("GCFB")) {
                    this.ivLength = this.baseEngine.getBlockSize();
                    this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new BufferedBlockCipher(new GCFBBlockCipher(this.baseEngine)));
                } else if (this.modeName.equals("CTS")) {
                    this.ivLength = this.baseEngine.getBlockSize();
                    this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new CTSBlockCipher(new CBCBlockCipher(this.baseEngine)));
                } else if (this.modeName.equals("CCM")) {
                    this.ivLength = 12;
                    if (this.baseEngine instanceof DSTU7624Engine) {
                        this.cipher = new BaseBlockCipher.AEADGenericBlockCipher(new KCCMBlockCipher(this.baseEngine));
                    } else {
                        this.cipher = new BaseBlockCipher.AEADGenericBlockCipher(new CCMBlockCipher(this.baseEngine));
                    }
                } else if (this.modeName.equals("OCB")) {
                    if (this.engineProvider == null) {
                        throw new NoSuchAlgorithmException("can't support mode " + mode);
                    }

                    this.ivLength = 15;
                    this.cipher = new BaseBlockCipher.AEADGenericBlockCipher(new OCBBlockCipher(this.baseEngine, this.engineProvider.get()));
                } else if (this.modeName.equals("EAX")) {
                    this.ivLength = this.baseEngine.getBlockSize();
                    this.cipher = new BaseBlockCipher.AEADGenericBlockCipher(new EAXBlockCipher(this.baseEngine));
                } else if (this.modeName.equals("GCM-SIV")) {
                    this.ivLength = 12;
                    this.cipher = new BaseBlockCipher.AEADGenericBlockCipher(new GCMSIVBlockCipher(this.baseEngine));
                } else {
                    if (!this.modeName.equals("GCM")) {
                        throw new NoSuchAlgorithmException("can't support mode " + mode);
                    }

                    if (this.baseEngine instanceof DSTU7624Engine) {
                        this.ivLength = this.baseEngine.getBlockSize();
                        this.cipher = new BaseBlockCipher.AEADGenericBlockCipher(new KGCMBlockCipher(this.baseEngine));
                    } else {
                        this.ivLength = 12;
                        this.cipher = new BaseBlockCipher.AEADGenericBlockCipher(new GCMBlockCipher(this.baseEngine));
                    }
                }
            }

        }
    }

    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (this.baseEngine == null) {
            throw new NoSuchPaddingException("no padding supported for this algorithm");
        } else {
            String paddingName = Strings.toUpperCase(padding);
            if (paddingName.equals("NOPADDING")) {
                if (this.cipher.wrapOnNoPadding()) {
                    this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new BufferedBlockCipher(this.cipher.getUnderlyingCipher()));
                }
            } else if (!paddingName.equals("WITHCTS") && !paddingName.equals("CTSPADDING") && !paddingName.equals("CS3PADDING")) {
                this.padded = true;
                if (this.isAEADModeName(this.modeName)) {
                    throw new NoSuchPaddingException("Only NoPadding can be used with AEAD modes.");
                }

                if (!paddingName.equals("PKCS5PADDING") && !paddingName.equals("PKCS7PADDING")) {
                    if (paddingName.equals("ZEROBYTEPADDING")) {
                        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(this.cipher.getUnderlyingCipher(), new ZeroBytePadding());
                    } else if (!paddingName.equals("ISO10126PADDING") && !paddingName.equals("ISO10126-2PADDING")) {
                        if (!paddingName.equals("X9.23PADDING") && !paddingName.equals("X923PADDING")) {
                            if (!paddingName.equals("ISO7816-4PADDING") && !paddingName.equals("ISO9797-1PADDING")) {
                                if (!paddingName.equals("TBCPADDING")) {
                                    throw new NoSuchPaddingException("Padding " + padding + " unknown.");
                                }

                                this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(this.cipher.getUnderlyingCipher(), new TBCPadding());
                            } else {
                                this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(this.cipher.getUnderlyingCipher(), new ISO7816d4Padding());
                            }
                        } else {
                            this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(this.cipher.getUnderlyingCipher(), new X923Padding());
                        }
                    } else {
                        this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(this.cipher.getUnderlyingCipher(), new ISO10126d2Padding());
                    }
                } else {
                    this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(this.cipher.getUnderlyingCipher());
                }
            } else {
                this.cipher = new BaseBlockCipher.BufferedGenericBlockCipher(new CTSBlockCipher(this.cipher.getUnderlyingCipher()));
            }

        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.pbeSpec = null;
        this.pbeAlgorithm = null;
        this.engineParams = null;
        this.aeadParams = null;
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Key for algorithm " + (key != null ? key.getAlgorithm() : null) + " not suitable for symmetric enryption.");
        } else if (params == null && this.baseEngine != null && this.baseEngine.getAlgorithmName().startsWith("RC5-64")) {
            throw new InvalidAlgorithmParameterException("RC5 requires an RC5ParametersSpec to be passed in.");
        } else {
            Object param;
            if (this.scheme != 2 && !(key instanceof PKCS12Key)) {
                if (key instanceof PBKDF1Key) {
                    PBKDF1Key k = (PBKDF1Key)key;
                    if (params instanceof PBEParameterSpec) {
                        this.pbeSpec = (PBEParameterSpec)params;
                    }

                    if (k instanceof PBKDF1KeyWithParameters && this.pbeSpec == null) {
                        this.pbeSpec = new PBEParameterSpec(((PBKDF1KeyWithParameters)k).getSalt(), ((PBKDF1KeyWithParameters)k).getIterationCount());
                    }

                    param = Util.makePBEParameters(k.getEncoded(), 0, this.digest, this.keySizeInBits, this.ivLength * 8, this.pbeSpec, this.cipher.getAlgorithmName());
                    if (param instanceof ParametersWithIV) {
                        this.ivParam = (ParametersWithIV)param;
                    }
                } else if (key instanceof BCPBEKey) {
                    BCPBEKey k = (BCPBEKey)key;
                    if (k.getOID() != null) {
                        this.pbeAlgorithm = k.getOID().getId();
                    } else {
                        this.pbeAlgorithm = k.getAlgorithm();
                    }

                    if (k.getParam() != null) {
                        param = this.adjustParameters(params, k.getParam());
                    } else {
                        if (!(params instanceof PBEParameterSpec)) {
                            throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
                        }

                        this.pbeSpec = (PBEParameterSpec)params;
                        param = Util.makePBEParameters(k, params, this.cipher.getUnderlyingCipher().getAlgorithmName());
                    }

                    if (param instanceof ParametersWithIV) {
                        this.ivParam = (ParametersWithIV)param;
                    }
                } else if (key instanceof PBEKey) {
                    PBEKey k = (PBEKey)key;
                    this.pbeSpec = (PBEParameterSpec)params;
                    if (k instanceof PKCS12KeyWithParameters && this.pbeSpec == null) {
                        this.pbeSpec = new PBEParameterSpec(k.getSalt(), k.getIterationCount());
                    }

                    param = Util.makePBEParameters(k.getEncoded(), this.scheme, this.digest, this.keySizeInBits, this.ivLength * 8, this.pbeSpec, this.cipher.getAlgorithmName());
                    if (param instanceof ParametersWithIV) {
                        this.ivParam = (ParametersWithIV)param;
                    }
                } else if (!(key instanceof RepeatedSecretKeySpec)) {
                    if (this.scheme == 0 || this.scheme == 4 || this.scheme == 1 || this.scheme == 5) {
                        throw new InvalidKeyException("Algorithm requires a PBE key");
                    }

                    param = new KeyParameter(key.getEncoded());
                } else {
                    param = null;
                }
            } else {
                SecretKey k;
                try {
                    k = (SecretKey)key;
                } catch (Exception var10) {
                    throw new InvalidKeyException("PKCS12 requires a SecretKey/PBEKey");
                }

                if (params instanceof PBEParameterSpec) {
                    this.pbeSpec = (PBEParameterSpec)params;
                }

                if (k instanceof PBEKey && this.pbeSpec == null) {
                    PBEKey pbeKey = (PBEKey)k;
                    if (pbeKey.getSalt() == null) {
                        throw new InvalidAlgorithmParameterException("PBEKey requires parameters to specify salt");
                    }

                    this.pbeSpec = new PBEParameterSpec(pbeKey.getSalt(), pbeKey.getIterationCount());
                }

                if (this.pbeSpec == null && !(k instanceof PBEKey)) {
                    throw new InvalidKeyException("Algorithm requires a PBE key");
                }

                if (key instanceof BCPBEKey) {
                    CipherParameters pbeKeyParam = ((BCPBEKey)key).getParam();
                    if (pbeKeyParam instanceof ParametersWithIV) {
                        param = pbeKeyParam;
                    } else {
                        if (pbeKeyParam != null) {
                            throw new InvalidKeyException("Algorithm requires a PBE key suitable for PKCS12");
                        }

                        param = Util.makePBEParameters(k.getEncoded(), 2, this.digest, this.keySizeInBits, this.ivLength * 8, this.pbeSpec, this.cipher.getAlgorithmName());
                    }
                } else {
                    param = Util.makePBEParameters(k.getEncoded(), 2, this.digest, this.keySizeInBits, this.ivLength * 8, this.pbeSpec, this.cipher.getAlgorithmName());
                }

                if (param instanceof ParametersWithIV) {
                    this.ivParam = (ParametersWithIV)param;
                }
            }

            if (params instanceof AEADParameterSpec) {
                if (!this.isAEADModeName(this.modeName) && !(this.cipher instanceof BaseBlockCipher.AEADGenericBlockCipher)) {
                    throw new InvalidAlgorithmParameterException("AEADParameterSpec can only be used with AEAD modes.");
                }

                AEADParameterSpec aeadSpec = (AEADParameterSpec)params;
                KeyParameter keyParam;
                if (param instanceof ParametersWithIV) {
                    keyParam = (KeyParameter)((ParametersWithIV)param).getParameters();
                } else {
                    keyParam = (KeyParameter)param;
                }

                param = this.aeadParams = new AEADParameters(keyParam, aeadSpec.getMacSizeInBits(), aeadSpec.getNonce(), aeadSpec.getAssociatedData());
            } else if (params instanceof IvParameterSpec) {
                if (this.ivLength != 0) {
                    IvParameterSpec p = (IvParameterSpec)params;
                    if (p.getIV().length != this.ivLength && !(this.cipher instanceof BaseBlockCipher.AEADGenericBlockCipher) && this.fixedIv) {
                        throw new InvalidAlgorithmParameterException("IV must be " + this.ivLength + " bytes long.");
                    }

                    if (param instanceof ParametersWithIV) {
                        param = new ParametersWithIV(((ParametersWithIV)param).getParameters(), p.getIV());
                    } else {
                        param = new ParametersWithIV((CipherParameters)param, p.getIV());
                    }

                    this.ivParam = (ParametersWithIV)param;
                } else if (this.modeName != null && this.modeName.equals("ECB")) {
                    throw new InvalidAlgorithmParameterException("ECB mode does not use an IV");
                }
            } else if (params instanceof GOST28147ParameterSpec) {
                GOST28147ParameterSpec gost28147Param = (GOST28147ParameterSpec)params;
                param = new ParametersWithSBox(new KeyParameter(key.getEncoded()), ((GOST28147ParameterSpec)params).getSbox());
                if (gost28147Param.getIV() != null && this.ivLength != 0) {
                    if (param instanceof ParametersWithIV) {
                        param = new ParametersWithIV(((ParametersWithIV)param).getParameters(), gost28147Param.getIV());
                    } else {
                        param = new ParametersWithIV((CipherParameters)param, gost28147Param.getIV());
                    }

                    this.ivParam = (ParametersWithIV)param;
                }
            } else if (params instanceof RC2ParameterSpec) {
                RC2ParameterSpec rc2Param = (RC2ParameterSpec)params;
                param = new RC2Parameters(key.getEncoded(), ((RC2ParameterSpec)params).getEffectiveKeyBits());
                if (rc2Param.getIV() != null && this.ivLength != 0) {
                    if (param instanceof ParametersWithIV) {
                        param = new ParametersWithIV(((ParametersWithIV)param).getParameters(), rc2Param.getIV());
                    } else {
                        param = new ParametersWithIV((CipherParameters)param, rc2Param.getIV());
                    }

                    this.ivParam = (ParametersWithIV)param;
                }
            } else if (params instanceof RC5ParameterSpec) {
                RC5ParameterSpec rc5Param = (RC5ParameterSpec)params;
                param = new RC5Parameters(key.getEncoded(), ((RC5ParameterSpec)params).getRounds());
                if (!this.baseEngine.getAlgorithmName().startsWith("RC5")) {
                    throw new InvalidAlgorithmParameterException("RC5 parameters passed to a cipher that is not RC5.");
                }

                if (this.baseEngine.getAlgorithmName().equals("RC5-32")) {
                    if (rc5Param.getWordSize() != 32) {
                        throw new InvalidAlgorithmParameterException("RC5 already set up for a word size of 32 not " + rc5Param.getWordSize() + ".");
                    }
                } else if (this.baseEngine.getAlgorithmName().equals("RC5-64") && rc5Param.getWordSize() != 64) {
                    throw new InvalidAlgorithmParameterException("RC5 already set up for a word size of 64 not " + rc5Param.getWordSize() + ".");
                }

                if (rc5Param.getIV() != null && this.ivLength != 0) {
                    if (param instanceof ParametersWithIV) {
                        param = new ParametersWithIV(((ParametersWithIV)param).getParameters(), rc5Param.getIV());
                    } else {
                        param = new ParametersWithIV((CipherParameters)param, rc5Param.getIV());
                    }

                    this.ivParam = (ParametersWithIV)param;
                }
            } else if (params instanceof FPEParameterSpec) {
                FPEParameterSpec spec = (FPEParameterSpec)params;
                param = new FPEParameters((KeyParameter)param, spec.getRadix(), spec.getTweak(), spec.isUsingInverseFunction());
            } else if (gcmSpecClass != null && gcmSpecClass.isInstance(params)) {
                if (!this.isAEADModeName(this.modeName) && !(this.cipher instanceof BaseBlockCipher.AEADGenericBlockCipher)) {
                    throw new InvalidAlgorithmParameterException("GCMParameterSpec can only be used with AEAD modes.");
                }

                KeyParameter keyParam;
                if (param instanceof ParametersWithIV) {
                    keyParam = (KeyParameter)((ParametersWithIV)param).getParameters();
                } else {
                    keyParam = (KeyParameter)param;
                }

                param = this.aeadParams = GcmSpecUtil.extractAeadParameters(keyParam, params);
            } else if (params != null && !(params instanceof PBEParameterSpec)) {
                throw new InvalidAlgorithmParameterException("unknown parameter type.");
            }

            if (this.ivLength != 0 && !(param instanceof ParametersWithIV) && !(param instanceof AEADParameters)) {
                SecureRandom ivRandom = random;
                if (random == null) {
                    ivRandom = CryptoServicesRegistrar.getSecureRandom();
                }

                if (opmode != 1 && opmode != 3) {
                    if (this.cipher.getUnderlyingCipher().getAlgorithmName().indexOf("PGPCFB") < 0) {
                        throw new InvalidAlgorithmParameterException("no IV set when one expected");
                    }
                } else {
                    byte[] iv = new byte[this.ivLength];
                    ivRandom.nextBytes(iv);
                    param = new ParametersWithIV((CipherParameters)param, iv);
                    this.ivParam = (ParametersWithIV)param;
                }
            }

            if (random != null && this.padded) {
                param = new ParametersWithRandom((CipherParameters)param, random);
            }

            try {
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
                        throw new InvalidParameterException("unknown opmode " + opmode + " passed");
                }

                if (this.cipher instanceof BaseBlockCipher.AEADGenericBlockCipher && this.aeadParams == null) {
                    AEADCipher aeadCipher = ((BaseBlockCipher.AEADGenericBlockCipher)this.cipher).cipher;
                    this.aeadParams = new AEADParameters((KeyParameter)this.ivParam.getParameters(), aeadCipher.getMac().length * 8, this.ivParam.getIV());
                }

            } catch (IllegalArgumentException var8) {
                throw new InvalidAlgorithmParameterException(var8.getMessage(), var8);
            } catch (Exception var9) {
                throw new InvalidKeyOrParametersException(var9.getMessage(), var9);
            }
        }
    }

    private CipherParameters adjustParameters(AlgorithmParameterSpec params, CipherParameters param) {
        IvParameterSpec iv;
        GOST28147ParameterSpec gost28147Param;
        if (param instanceof ParametersWithIV) {
            CipherParameters key = ((ParametersWithIV)param).getParameters();
            if (params instanceof IvParameterSpec) {
                iv = (IvParameterSpec)params;
                this.ivParam = new ParametersWithIV(key, iv.getIV());
                param = this.ivParam;
            } else if (params instanceof GOST28147ParameterSpec) {
                gost28147Param = (GOST28147ParameterSpec)params;
                param = new ParametersWithSBox((CipherParameters)param, gost28147Param.getSbox());
                if (gost28147Param.getIV() != null && this.ivLength != 0) {
                    this.ivParam = new ParametersWithIV(key, gost28147Param.getIV());
                    param = this.ivParam;
                }
            }
        } else if (params instanceof IvParameterSpec) {
            iv = (IvParameterSpec)params;
            this.ivParam = new ParametersWithIV((CipherParameters)param, iv.getIV());
            param = this.ivParam;
        } else if (params instanceof GOST28147ParameterSpec) {
            gost28147Param = (GOST28147ParameterSpec)params;
            param = new ParametersWithSBox((CipherParameters)param, gost28147Param.getSbox());
            if (gost28147Param.getIV() != null && this.ivLength != 0) {
                param = new ParametersWithIV((CipherParameters)param, gost28147Param.getIV());
            }
        }

        return (CipherParameters)param;
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec paramSpec = null;
        if (params != null) {
            paramSpec = SpecUtil.extractSpec(params, this.availableSpecs);
            if (paramSpec == null) {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + params.toString());
            }
        }

        this.engineInit(opmode, key, paramSpec, random);
        this.engineParams = params;
    }

    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            this.engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        } catch (InvalidAlgorithmParameterException var5) {
            throw new InvalidKeyException(var5.getMessage());
        }
    }

    protected void engineUpdateAAD(byte[] input, int offset, int length) {
        this.cipher.updateAAD(input, offset, length);
    }

    protected void engineUpdateAAD(ByteBuffer src) {
        int remaining = src.remaining();
        if (remaining >= 1) {
            if (src.hasArray()) {
                this.engineUpdateAAD(src.array(), src.arrayOffset() + src.position(), remaining);
                src.position(src.limit());
            } else {
                byte[] data;
                if (remaining <= 512) {
                    data = new byte[remaining];
                    src.get(data);
                    this.engineUpdateAAD(data, 0, data.length);
                    Arrays.fill(data, (byte)0);
                } else {
                    data = new byte[512];

                    do {
                        int length = Math.min(data.length, remaining);
                        src.get(data, 0, length);
                        this.engineUpdateAAD(data, 0, length);
                        remaining -= length;
                    } while(remaining > 0);

                    Arrays.fill(data, (byte)0);
                }
            }
        }

    }

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        int length = this.cipher.getUpdateOutputSize(inputLen);
        if (length > 0) {
            byte[] out = new byte[length];
            int len = this.cipher.processBytes(input, inputOffset, inputLen, out, 0);
            if (len == 0) {
                return null;
            } else if (len != out.length) {
                byte[] tmp = new byte[len];
                System.arraycopy(out, 0, tmp, 0, len);
                return tmp;
            } else {
                return out;
            }
        } else {
            this.cipher.processBytes(input, inputOffset, inputLen, (byte[])null, 0);
            return null;
        }
    }

    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        if (outputOffset + this.cipher.getUpdateOutputSize(inputLen) > output.length) {
            throw new ShortBufferException("output buffer too short for input.");
        } else {
            try {
                return this.cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);
            } catch (DataLengthException var7) {
                throw new IllegalStateException(var7.toString());
            }
        }
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
        }

        if (len == tmp.length) {
            return tmp;
        } else if (len > tmp.length) {
            throw new IllegalBlockSizeException("internal buffer overflow");
        } else {
            byte[] out = new byte[len];
            System.arraycopy(tmp, 0, out, 0, len);
            return out;
        }
    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
        int len = 0;
        if (outputOffset + this.engineGetOutputSize(inputLen) > output.length) {
            throw new ShortBufferException("output buffer too short for input.");
        } else {
            try {
                if (inputLen != 0) {
                    len = this.cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);
                }

                return len + this.cipher.doFinal(output, outputOffset + len);
            } catch (OutputLengthException var8) {
                throw new IllegalBlockSizeException(var8.getMessage());
            } catch (DataLengthException var9) {
                throw new IllegalBlockSizeException(var9.getMessage());
            }
        }
    }

    private boolean isAEADModeName(String modeName) {
        return "CCM".equals(modeName) || "EAX".equals(modeName) || "GCM".equals(modeName) || "GCM-SIV".equals(modeName) || "OCB".equals(modeName);
    }

    private static class AEADGenericBlockCipher implements BaseBlockCipher.GenericBlockCipher {
        private static final Constructor aeadBadTagConstructor;
        private AEADCipher cipher;

        private static Constructor findExceptionConstructor(Class clazz) {
            try {
                return clazz.getConstructor(String.class);
            } catch (Exception var2) {
                return null;
            }
        }

        AEADGenericBlockCipher(AEADCipher cipher) {
            this.cipher = cipher;
        }

        public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
            this.cipher.init(forEncryption, params);
        }

        public String getAlgorithmName() {
            return this.cipher instanceof AEADBlockCipher ? ((AEADBlockCipher)this.cipher).getUnderlyingCipher().getAlgorithmName() : this.cipher.getAlgorithmName();
        }

        public boolean wrapOnNoPadding() {
            return false;
        }

        public BlockCipher getUnderlyingCipher() {
            return this.cipher instanceof AEADBlockCipher ? ((AEADBlockCipher)this.cipher).getUnderlyingCipher() : null;
        }

        public int getOutputSize(int len) {
            return this.cipher.getOutputSize(len);
        }

        public int getUpdateOutputSize(int len) {
            return this.cipher.getUpdateOutputSize(len);
        }

        public void updateAAD(byte[] input, int offset, int length) {
            this.cipher.processAADBytes(input, offset, length);
        }

        public int processByte(byte in, byte[] out, int outOff) throws DataLengthException {
            return this.cipher.processByte(in, out, outOff);
        }

        public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
            return this.cipher.processBytes(in, inOff, len, out, outOff);
        }

        public int doFinal(byte[] out, int outOff) throws IllegalStateException, BadPaddingException {
            try {
                return this.cipher.doFinal(out, outOff);
            } catch (InvalidCipherTextException var7) {
                InvalidCipherTextException e = var7;
                if (aeadBadTagConstructor != null) {
                    BadPaddingException aeadBadTag = null;

                    try {
                        aeadBadTag = (BadPaddingException)aeadBadTagConstructor.newInstance(e.getMessage());
                    } catch (Exception var6) {
                    }

                    if (aeadBadTag != null) {
                        throw aeadBadTag;
                    }
                }

                throw new BadPaddingException(var7.getMessage());
            }
        }

        static {
            Class aeadBadTagClass = ClassUtil.loadClass(BaseBlockCipher.class, "javax.crypto.AEADBadTagException");
            if (aeadBadTagClass != null) {
                aeadBadTagConstructor = findExceptionConstructor(aeadBadTagClass);
            } else {
                aeadBadTagConstructor = null;
            }

        }
    }

    private static class BufferedFPEBlockCipher implements BaseBlockCipher.GenericBlockCipher {
        private FPEEngine cipher;
        private ErasableOutputStream eOut = new ErasableOutputStream();

        BufferedFPEBlockCipher(FPEEngine cipher) {
            this.cipher = cipher;
        }

        public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
            this.cipher.init(forEncryption, params);
        }

        public boolean wrapOnNoPadding() {
            return false;
        }

        public String getAlgorithmName() {
            return this.cipher.getAlgorithmName();
        }

        public BlockCipher getUnderlyingCipher() {
            throw new IllegalStateException("not applicable for FPE");
        }

        public int getOutputSize(int len) {
            return this.eOut.size() + len;
        }

        public int getUpdateOutputSize(int len) {
            return 0;
        }

        public void updateAAD(byte[] input, int offset, int length) {
            throw new UnsupportedOperationException("AAD is not supported in the current mode.");
        }

        public int processByte(byte in, byte[] out, int outOff) throws DataLengthException {
            this.eOut.write(in);
            return 0;
        }

        public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
            this.eOut.write(in, inOff, len);
            return 0;
        }

        public int doFinal(byte[] out, int outOff) throws IllegalStateException, BadPaddingException {
            int var3;
            try {
                var3 = this.cipher.processBlock(this.eOut.getBuf(), 0, this.eOut.size(), out, outOff);
            } finally {
                this.eOut.erase();
            }

            return var3;
        }
    }

    private static class BufferedGenericBlockCipher implements BaseBlockCipher.GenericBlockCipher {
        private BufferedBlockCipher cipher;

        BufferedGenericBlockCipher(BufferedBlockCipher cipher) {
            this.cipher = cipher;
        }

        BufferedGenericBlockCipher(BlockCipher cipher) {
            this.cipher = new PaddedBufferedBlockCipher(cipher);
        }

        BufferedGenericBlockCipher(BlockCipher cipher, BlockCipherPadding padding) {
            this.cipher = new PaddedBufferedBlockCipher(cipher, padding);
        }

        public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
            this.cipher.init(forEncryption, params);
        }

        public boolean wrapOnNoPadding() {
            return !(this.cipher instanceof CTSBlockCipher);
        }

        public String getAlgorithmName() {
            return this.cipher.getUnderlyingCipher().getAlgorithmName();
        }

        public BlockCipher getUnderlyingCipher() {
            return this.cipher.getUnderlyingCipher();
        }

        public int getOutputSize(int len) {
            return this.cipher.getOutputSize(len);
        }

        public int getUpdateOutputSize(int len) {
            return this.cipher.getUpdateOutputSize(len);
        }

        public void updateAAD(byte[] input, int offset, int length) {
            throw new UnsupportedOperationException("AAD is not supported in the current mode.");
        }

        public int processByte(byte in, byte[] out, int outOff) throws DataLengthException {
            return this.cipher.processByte(in, out, outOff);
        }

        public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
            return this.cipher.processBytes(in, inOff, len, out, outOff);
        }

        public int doFinal(byte[] out, int outOff) throws IllegalStateException, BadPaddingException {
            try {
                return this.cipher.doFinal(out, outOff);
            } catch (InvalidCipherTextException var4) {
                throw new BadPaddingException(var4.getMessage());
            }
        }
    }

    private interface GenericBlockCipher {
        void init(boolean var1, CipherParameters var2) throws IllegalArgumentException;

        boolean wrapOnNoPadding();

        String getAlgorithmName();

        BlockCipher getUnderlyingCipher();

        int getOutputSize(int var1);

        int getUpdateOutputSize(int var1);

        void updateAAD(byte[] var1, int var2, int var3);

        int processByte(byte var1, byte[] var2, int var3) throws DataLengthException;

        int processBytes(byte[] var1, int var2, int var3, byte[] var4, int var5) throws DataLengthException;

        int doFinal(byte[] var1, int var2) throws IllegalStateException, BadPaddingException;
    }
}