package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.params.DHParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAParameters;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.EC5Util;
import com.mi.car.jsse.easysec.jcajce.provider.config.ConfigurableProvider;
import com.mi.car.jsse.easysec.jcajce.provider.config.ProviderConfiguration;
import com.mi.car.jsse.easysec.jcajce.provider.config.ProviderConfigurationPermission;
import com.mi.car.jsse.easysec.jcajce.spec.DHDomainParameterSpec;
import com.mi.car.jsse.easysec.jce.spec.ECParameterSpec;
import java.security.Permission;
import java.security.spec.DSAParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.crypto.spec.DHParameterSpec;

class EasysecProviderConfiguration implements ProviderConfiguration {
    private static Permission BC_EC_LOCAL_PERMISSION = new ProviderConfigurationPermission("ES", "threadLocalEcImplicitlyCa");
    private static Permission BC_EC_PERMISSION = new ProviderConfigurationPermission("ES", "ecImplicitlyCa");
    private static Permission BC_DH_LOCAL_PERMISSION = new ProviderConfigurationPermission("ES", "threadLocalDhDefaultParams");
    private static Permission BC_DH_PERMISSION = new ProviderConfigurationPermission("ES", "DhDefaultParams");
    private static Permission BC_EC_CURVE_PERMISSION = new ProviderConfigurationPermission("ES", "acceptableEcCurves");
    private static Permission BC_ADDITIONAL_EC_CURVE_PERMISSION = new ProviderConfigurationPermission("ES", "additionalEcParameters");
    private ThreadLocal ecThreadSpec = new ThreadLocal();
    private ThreadLocal dhThreadSpec = new ThreadLocal();
    private volatile ECParameterSpec ecImplicitCaParams;
    private volatile Object dhDefaultParams;
    private volatile Set acceptableNamedCurves = new HashSet();
    private volatile Map additionalECParameters = new HashMap();

    EasysecProviderConfiguration() {
    }

    void setParameter(String parameterName, Object parameter) {
        SecurityManager securityManager = System.getSecurityManager();
        if (parameterName.equals("threadLocalEcImplicitlyCa")) {
            if (securityManager != null) {
                securityManager.checkPermission(BC_EC_LOCAL_PERMISSION);
            }

            ECParameterSpec curveSpec;
            if (!(parameter instanceof ECParameterSpec) && parameter != null) {
                curveSpec = EC5Util.convertSpec((java.security.spec.ECParameterSpec)parameter);
            } else {
                curveSpec = (ECParameterSpec)parameter;
            }

            if (curveSpec == null) {
                this.ecThreadSpec.remove();
            } else {
                this.ecThreadSpec.set(curveSpec);
            }
        } else if (parameterName.equals("ecImplicitlyCa")) {
            if (securityManager != null) {
                securityManager.checkPermission(BC_EC_PERMISSION);
            }

            if (!(parameter instanceof ECParameterSpec) && parameter != null) {
                this.ecImplicitCaParams = EC5Util.convertSpec((java.security.spec.ECParameterSpec)parameter);
            } else {
                this.ecImplicitCaParams = (ECParameterSpec)parameter;
            }
        } else if (parameterName.equals("threadLocalDhDefaultParams")) {
            if (securityManager != null) {
                securityManager.checkPermission(BC_DH_LOCAL_PERMISSION);
            }

            if (!(parameter instanceof DHParameterSpec) && !(parameter instanceof DHParameterSpec[]) && parameter != null) {
                throw new IllegalArgumentException("not a valid DHParameterSpec");
            }

            if (parameter == null) {
                this.dhThreadSpec.remove();
            } else {
                this.dhThreadSpec.set(parameter);
            }
        } else if (parameterName.equals("DhDefaultParams")) {
            if (securityManager != null) {
                securityManager.checkPermission(BC_DH_PERMISSION);
            }

            if (!(parameter instanceof DHParameterSpec) && !(parameter instanceof DHParameterSpec[]) && parameter != null) {
                throw new IllegalArgumentException("not a valid DHParameterSpec or DHParameterSpec[]");
            }

            this.dhDefaultParams = parameter;
        } else if (parameterName.equals("acceptableEcCurves")) {
            if (securityManager != null) {
                securityManager.checkPermission(BC_EC_CURVE_PERMISSION);
            }

            this.acceptableNamedCurves = (Set)parameter;
        } else if (parameterName.equals("additionalEcParameters")) {
            if (securityManager != null) {
                securityManager.checkPermission(BC_ADDITIONAL_EC_CURVE_PERMISSION);
            }

            this.additionalECParameters = (Map)parameter;
        }

    }

    public ECParameterSpec getEcImplicitlyCa() {
        ECParameterSpec spec = (ECParameterSpec)this.ecThreadSpec.get();
        return spec != null ? spec : this.ecImplicitCaParams;
    }

    public DHParameterSpec getDHDefaultParameters(int keySize) {
        Object params = this.dhThreadSpec.get();
        if (params == null) {
            params = this.dhDefaultParams;
        }

        if (params instanceof DHParameterSpec) {
            DHParameterSpec spec = (DHParameterSpec)params;
            if (spec.getP().bitLength() == keySize) {
                return spec;
            }
        } else if (params instanceof DHParameterSpec[]) {
            DHParameterSpec[] specs = (DHParameterSpec[])((DHParameterSpec[])params);

            for(int i = 0; i != specs.length; ++i) {
                if (specs[i].getP().bitLength() == keySize) {
                    return specs[i];
                }
            }
        }

        DHParameters dhParams = (DHParameters)CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DH_DEFAULT_PARAMS, keySize);
        return dhParams != null ? new DHDomainParameterSpec(dhParams) : null;
    }

    public DSAParameterSpec getDSADefaultParameters(int keySize) {
        DSAParameters dsaParams = (DSAParameters)CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DSA_DEFAULT_PARAMS, keySize);
        return dsaParams != null ? new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG()) : null;
    }

    public Set getAcceptableNamedCurves() {
        return Collections.unmodifiableSet(this.acceptableNamedCurves);
    }

    public Map getAdditionalECParameters() {
        return Collections.unmodifiableMap(this.additionalECParameters);
    }
}
