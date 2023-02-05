package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.jcajce.PKIXCRLStoreSelector;
import com.mi.car.jsse.easysec.util.Store;
import com.mi.car.jsse.easysec.util.StoreException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

abstract class PKIXCRLUtil {
    PKIXCRLUtil() {
    }

    static Set findCRLs(PKIXCRLStoreSelector crlselect, Date validityDate, List certStores, List pkixCrlStores) throws AnnotatedException {
        X509Certificate cert;
        HashSet initialSet = new HashSet();
        try {
            findCRLs(initialSet, crlselect, pkixCrlStores);
            findCRLs(initialSet, crlselect, certStores);
            Set finalSet = new HashSet();
            Iterator it = initialSet.iterator();
            while (it.hasNext()) {
                X509CRL crl = (X509CRL) it.next();
                Date nextUpdate = crl.getNextUpdate();
                if ((nextUpdate == null || nextUpdate.after(validityDate)) && ((cert = crlselect.getCertificateChecking()) == null || crl.getThisUpdate().before(cert.getNotAfter()))) {
                    finalSet.add(crl);
                }
            }
            return finalSet;
        } catch (AnnotatedException e) {
            throw new AnnotatedException("Exception obtaining complete CRLs.", e);
        }
    }

    private static void findCRLs(HashSet crls, PKIXCRLStoreSelector crlSelect, List crlStores) throws AnnotatedException {
        AnnotatedException lastException = null;
        boolean foundValidStore = false;
        for (Object obj : crlStores) {
            if (obj instanceof Store) {
                try {
                    crls.addAll(((Store) obj).getMatches(crlSelect));
                    foundValidStore = true;
                } catch (StoreException e) {
                    lastException = new AnnotatedException("Exception searching in X.509 CRL store.", e);
                }
            } else {
                try {
                    crls.addAll(PKIXCRLStoreSelector.getCRLs(crlSelect, (CertStore) obj));
                    foundValidStore = true;
                } catch (CertStoreException e2) {
                    lastException = new AnnotatedException("Exception searching in X.509 CRL store.", e2);
                }
            }
        }
        if (!(foundValidStore || lastException == null)) {
            throw lastException;
        }
    }
}
