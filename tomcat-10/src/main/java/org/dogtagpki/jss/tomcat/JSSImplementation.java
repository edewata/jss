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
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK */

package org.dogtagpki.jss.tomcat;

import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLSession;

import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLImplementation;
import org.apache.tomcat.util.net.SSLSupport;
import org.apache.tomcat.util.net.SSLUtil;
import org.apache.tomcat.util.net.jsse.JSSESupport;
import org.mozilla.jss.netscape.security.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * https://github.com/apache/tomcat/blob/10.1.x/java/org/apache/tomcat/util/net/SSLImplementation.java
 */
public class JSSImplementation extends SSLImplementation {

    public static final Logger logger = LoggerFactory.getLogger(JSSImplementation.class);

    public JSSImplementation() {
        logger.debug("JSSImplementation: instance created");
    }

    @Override
    public SSLSupport getSSLSupport(SSLSession session, Map<String, List<String>> additionalAttributes) {
        logger.debug("JSSImplementation: getSSLSupport()");
        logger.debug("JSSImplementation: - session: {}", Utils.HexEncode(session.getId()));
        for (String name : additionalAttributes.keySet()) {
            List<String> values = additionalAttributes.get(name);
            logger.debug("JSSImplementation: - {}: {}", name, values);
        }
        return new JSSESupport(session, additionalAttributes);
    }

    @Override
    public SSLUtil getSSLUtil(SSLHostConfigCertificate cert) {
        logger.debug("JSSImplementation: getSSLUtil()");
        logger.debug("JSSImplementation: - key alias: {}", cert.getCertificateKeyAlias());
        logger.debug("JSSImplementation: - keystore provider: {}", cert.getCertificateKeystoreProvider());

        SSLHostConfig hostConfig = cert.getSSLHostConfig();
        logger.debug("JSSImplementation: - key manager alg: {}", hostConfig.getKeyManagerAlgorithm());
        logger.debug("JSSImplementation: - truststore alg: {}", hostConfig.getTruststoreAlgorithm());
        logger.debug("JSSImplementation: - truststore provider: {}", hostConfig.getTruststoreProvider());

        return new JSSUtil(cert);
    }
}
