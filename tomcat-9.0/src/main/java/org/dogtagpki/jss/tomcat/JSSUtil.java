/* BEGIN COPYRIGHT BLOCK
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Copyright (C) 2018 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK */

package org.dogtagpki.jss.tomcat;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.SSLContext;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLUtilBase;
import org.mozilla.jss.JSSProvider;
import org.mozilla.jss.crypto.Policy;
import org.mozilla.jss.provider.javax.crypto.JSSNativeTrustManager;
import org.mozilla.jss.ssl.SSLCipher;
import org.mozilla.jss.ssl.SSLVersion;

public class JSSUtil extends SSLUtilBase {
    public static Log logger = LogFactory.getLog(JSSUtil.class);

    private String keyAlias;

    private Set<String> protocols;
    private Set<String> ciphers;

    public JSSUtil(SSLHostConfigCertificate cert) {
        super(cert);

        keyAlias = certificate.getCertificateKeyAlias();
        logger.debug("JSSUtil: instance created");
    }

    @Override
    public KeyManager[] getKeyManagers() throws Exception {
        logger.debug("JSSUtil: getKeyManagers()");
        KeyManagerFactory jkm = KeyManagerFactory.getInstance("NssX509", "Mozilla-JSS");
        return jkm.getKeyManagers();
    }

    @Override
    public TrustManager[] getTrustManagers() throws Exception {
        logger.debug("JSSUtil: getTrustManagers()");
        if (!JSSProvider.ENABLE_JSSENGINE) {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("NssX509");
            return tmf.getTrustManagers();
        }

        return new TrustManager[] { new JSSNativeTrustManager() };
    }

    @Override
    public SSLContext createSSLContextInternal(List<String> negotiableProtocols) throws Exception {
        logger.debug("JSSUtil createSSLContextInternal(...) keyAlias=" + keyAlias);
        return new JSSContext(keyAlias);
    }

    @Override
    public boolean isTls13RenegAuthAvailable() {
        logger.debug("JSSUtil: isTls13RenegAuthAvailable()");
        return true;
    }

    @Override
    public Log getLog() {
        logger.debug("JSSUtil: getLog()");
        return logger;
    }

    @Override
    protected Set<String> getImplementedProtocols() {

        if (protocols != null) {
            return protocols;
        }

        logger.warn("JSSUtil: getImplementedProtocols()");
        protocols = new HashSet<>();
        for (SSLVersion v : Policy.TLS_VERSION_RANGE.getAllInRange()) {
            logger.warn("JSSUtil: - " + v);
            protocols.add(v.jdkAlias());
        }

        return protocols;
    }

    @Override
    protected Set<String> getImplementedCiphers() {

        if (ciphers != null) {
            return ciphers;
        }

        logger.warn("JSSUtil: getImplementedCiphers()");
        ciphers = new HashSet<>();
        for (SSLCipher c : SSLCipher.values()) {
            if (!c.isSupported()) continue;
            logger.warn("JSSUtil: - " + c);
            ciphers.add(c.name());
        }

        return ciphers;
    }
}
