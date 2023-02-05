package com.mi.car.jsse.easysec.jcajce.util;

import java.security.Provider;
import java.security.Security;

import com.mi.car.jsse.easysec.jce.provider.EasysecProvider;

/**
 * A JCA/JCE helper that refers to the BC provider for all it's needs.
 */
public class BCJcaJceHelper
    extends ProviderJcaJceHelper
{
    private static volatile Provider bcProvider;

    private static synchronized Provider getEasysecProvider()
    {
        final Provider system = Security.getProvider("BC");
        // Avoid using the old, deprecated system BC provider on Android.
        // See: https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html
        if (system instanceof EasysecProvider)
        {
            return system;
        }
        else if (bcProvider != null)
        {
            return bcProvider;
        }
        else
        {
            bcProvider = new EasysecProvider();

            return bcProvider;
        }
    }

    public BCJcaJceHelper()
    {
        super(getEasysecProvider());
    }
}
