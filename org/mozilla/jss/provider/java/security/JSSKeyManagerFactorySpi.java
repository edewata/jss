/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.java.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.ManagerFactoryParameters;

import org.mozilla.jss.crypto.TokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The JSS implementation of the JCA KeyManagerFactory SPI.
 */
public class JSSKeyManagerFactorySpi extends javax.net.ssl.KeyManagerFactorySpi {

    public static Logger logger = LoggerFactory.getLogger(JSSKeyManagerFactorySpi.class);

    public JSSKeyManagerFactorySpi() throws TokenException {
        logger.debug("JSSKeyManagerFactorySpi: initialization");
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        logger.debug("JSSKeyManagerFactorySpi: engineInit()");
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        logger.debug("JSSKeyManagerFactorySpi: engineGetKeyManagers()");
        return null;
    }

    @Override
    protected void engineInit(KeyStore ks, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        logger.debug("JSSKeyManagerFactorySpi: engineInit(" + ks.getClass().getName() + ")");
    }
}
