package com.mi.car.jsse.easysec.jcajce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import com.mi.car.jsse.easysec.asn1.kisa.KISAObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherKeyGenerator;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.engines.SEEDEngine;
import com.mi.car.jsse.easysec.crypto.engines.SEEDWrapEngine;
import com.mi.car.jsse.easysec.crypto.generators.Poly1305KeyGenerator;
import com.mi.car.jsse.easysec.crypto.macs.CMac;
import com.mi.car.jsse.easysec.crypto.macs.GMac;
import com.mi.car.jsse.easysec.crypto.modes.CBCBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.GCMBlockCipher;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseBlockCipher;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseMac;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseWrapCipher;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BlockCipherProvider;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.IvAlgorithmParameters;

public final class SEED
{
    private SEED()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new SEEDEngine();
                }
            });
        }
    }

    public static class CBC
       extends BaseBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new SEEDEngine()), 128);
        }
    }

    public static class Wrap
        extends BaseWrapCipher
    {
        public Wrap()
        {
            super(new SEEDWrapEngine());
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("SEED", 128, new CipherKeyGenerator());
        }
    }

    public static class CMAC
        extends BaseMac
    {
        public CMAC()
        {
            super(new CMac(new SEEDEngine()));
        }
    }

    public static class GMAC
        extends BaseMac
    {
        public GMAC()
        {
            super(new GMac(new GCMBlockCipher(new SEEDEngine())));
        }
    }

    static public class KeyFactory
         extends BaseSecretKeyFactory
    {
        public KeyFactory()
        {
            super("SEED", null);
        }
    }

    public static class Poly1305
        extends BaseMac
    {
        public Poly1305()
        {
            super(new com.mi.car.jsse.easysec.crypto.macs.Poly1305(new SEEDEngine()));
        }
    }

    public static class Poly1305KeyGen
        extends BaseKeyGenerator
    {
        public Poly1305KeyGen()
        {
            super("Poly1305-SEED", 256, new Poly1305KeyGenerator());
        }
    }

    public static class AlgParamGen
        extends BaseAlgorithmParameterGenerator
    {
        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for SEED parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[] iv = new byte[16];

            if (random == null)
            {
                random = CryptoServicesRegistrar.getSecureRandom();
            }

            random.nextBytes(iv);

            AlgorithmParameters params;

            try
            {
                params = createParametersInstance("SEED");
                params.init(new IvParameterSpec(iv));
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.getMessage());
            }

            return params;
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "SEED IV";
        }
    }

    public static class Mappings
        extends SymmetricAlgorithmProvider
    {
        private static final String PREFIX = SEED.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("AlgorithmParameters.SEED", PREFIX + "$AlgParams");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + KISAObjectIdentifiers.id_seedCBC, "SEED");

            provider.addAlgorithm("AlgorithmParameterGenerator.SEED", PREFIX + "$AlgParamGen");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + KISAObjectIdentifiers.id_seedCBC, "SEED");

            provider.addAlgorithm("Cipher.SEED", PREFIX + "$ECB");
            provider.addAlgorithm("Cipher", KISAObjectIdentifiers.id_seedCBC, PREFIX + "$CBC");

            provider.addAlgorithm("Cipher.SEEDWRAP", PREFIX + "$Wrap");
            provider.addAlgorithm("Alg.Alias.Cipher", KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap, "SEEDWRAP");
            provider.addAlgorithm("Alg.Alias.Cipher.SEEDKW", "SEEDWRAP");

            provider.addAlgorithm("KeyGenerator.SEED", PREFIX + "$KeyGen");
            provider.addAlgorithm("KeyGenerator", KISAObjectIdentifiers.id_seedCBC, PREFIX + "$KeyGen");
            provider.addAlgorithm("KeyGenerator", KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap, PREFIX + "$KeyGen");

            provider.addAlgorithm("SecretKeyFactory.SEED", PREFIX + "$KeyFactory");
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory", KISAObjectIdentifiers.id_seedCBC, "SEED");

            addCMacAlgorithm(provider, "SEED", PREFIX + "$CMAC", PREFIX + "$KeyGen");
            addGMacAlgorithm(provider, "SEED", PREFIX + "$GMAC", PREFIX + "$KeyGen");
            addPoly1305Algorithm(provider, "SEED", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
        }
    }
}
