package com.mi.car.jsse.easysec.jcajce.provider.digest;

import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.CipherKeyGenerator;
import com.mi.car.jsse.easysec.crypto.digests.MD2Digest;
import com.mi.car.jsse.easysec.crypto.macs.HMac;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.mi.car.jsse.easysec.jcajce.provider.symmetric.util.BaseMac;

public class MD2
{
    private MD2()
    {

    }

    static public class Digest
        extends BCMessageDigest
        implements Cloneable
    {
        public Digest()
        {
            super(new MD2Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Digest d = (Digest)super.clone();
            d.digest = new MD2Digest((MD2Digest)digest);

            return d;
        }
    }

    /**
     * MD2 HMac
     */
    public static class HashMac
        extends BaseMac
    {
        public HashMac()
        {
            super(new HMac(new MD2Digest()));
        }
    }

    public static class KeyGenerator
        extends BaseKeyGenerator
    {
        public KeyGenerator()
        {
            super("HMACMD2", 128, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = MD2.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.MD2", PREFIX + "$Digest");
            provider.addAlgorithm("Alg.Alias.MessageDigest." + PKCSObjectIdentifiers.md2, "MD2");

            addHMACAlgorithm(provider, "MD2", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
        }
    }
}
