package com.mi.car.jsse.easysec.jsse.util;

import com.mi.car.jsse.easysec.jsse.BCSNIHostName;
import com.mi.car.jsse.easysec.util.IPAddress;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SNIUtil {
    private static final Logger LOG = Logger.getLogger(SNIUtil.class.getName());

    public static BCSNIHostName getBCSNIHostName(URL url) {
        String host;
        if (url != null && (host = url.getHost()) != null && host.indexOf(46) > 0 && !IPAddress.isValid(host)) {
            try {
                return new BCSNIHostName(host);
            } catch (Exception e) {
                LOG.log(Level.FINER, "Failed to parse BCSNIHostName from URL: " + url, (Throwable) e);
            }
        }
        return null;
    }
}
