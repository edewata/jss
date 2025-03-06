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
 * Copyright (C) 2017 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK */
package org.dogtagpki.jss.tomcat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.coyote.http11.AbstractHttp11JsseProtocol;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.NioChannel;
import org.dogtagpki.jss.JSS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Http11NioProtocol extends AbstractHttp11JsseProtocol<NioChannel> {

    public static Logger logger = LoggerFactory.getLogger(Http11NioProtocol.class);
    private static final Log log = LogFactory.getLog(Http11NioProtocol.class);

    JSS jss = JSS.getInstance();

    public Http11NioProtocol() {
       super(new JSSNioEndpoint());
    }

    public String getCertdbDir() {
        return jss.getCertdbDir();
    }

    public void setCertdbDir(String certdbDir) {
        jss.setCertdbDir(certdbDir);
    }

    public String getPasswordClass() {
        return jss.getPasswordClass();
    }

    public void setPasswordClass(String passwordClass) {
        jss.setPasswordClass(passwordClass);
    }

    public String getPasswordFile() {
        return jss.getPasswordFile();
    }

    public void setPasswordFile(String passwordFile) {
        jss.setPasswordFile(passwordFile);
    }

    public String getServerCertNickFile() {
        return jss.getServerCertNickFile();
    }

    public void setServerCertNickFile(String serverCertNickFile) {
        jss.setServerCertNickFile(serverCertNickFile);
    }

    public boolean getEnableOCSP() {
        return jss.getEnableRevocationCheck();
    }

    public void setEnableOCSP(boolean enableOCSP) {
        jss.setEnableRevocationCheck(enableOCSP);
    }

    public boolean getEnableRevocationCheck() {
        return jss.getEnableRevocationCheck();
    }

    public void setEnableRevocationCheck(boolean enableRevocationCheck) {
        jss.setEnableRevocationCheck(enableRevocationCheck);
    }

    public String getOcspResponderURL() {
        return jss.getOcspResponderURL();
    }

    public void setOcspResponderURL(String ocspResponderURL) {
        jss.setOcspResponderURL(ocspResponderURL);
    }

    public String getOcspResponderCertNickname() {
        return jss.getOcspResponderCertNickname();
    }

    public void setOcspResponderCertNickname(String ocspResponderCertNickname) {
        jss.setOcspResponderCertNickname(ocspResponderCertNickname);
    }

    public int getOcspCacheSize() {
        return jss.getOcspCacheSize();
    }

    public void setOcspCacheSize(int ocspCacheSize) {
        jss.setOcspCacheSize(ocspCacheSize);
    }

    public int getOcspMinCacheEntryDuration() {
        return jss.getOcspMinCacheEntryDuration();
    }

    public void setOcspMinCacheEntryDuration(int ocspMinCacheEntryDuration) {
        jss.setOcspMinCacheEntryDuration(ocspMinCacheEntryDuration);
    }

    public int getOcspMaxCacheEntryDuration() {
        return jss.getOcspMaxCacheEntryDuration();
    }

    public void setOcspMaxCacheEntryDuration(int ocspMaxCacheEntryDuration) {
        jss.setOcspMaxCacheEntryDuration(ocspMaxCacheEntryDuration);
    }

    public int getOcspTimeout() {
        return jss.getOcspTimeout();
    }

    public void setOcspTimeout(int ocspTimeout) {
        jss.setOcspTimeout(ocspTimeout);
    }

    public void setKeystorePassFile(String keystorePassFile) {
        try {
            Path path = Paths.get(keystorePassFile);
            String password = new String(Files.readAllBytes(path)).trim();
            setKeystorePass(password);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void setTruststorePassFile(String truststorePassFile) {
        try {
            Path path = Paths.get(truststorePassFile);
            String password = new String(Files.readAllBytes(path)).trim();
            setTruststorePass(password);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected Log getLog() {
        return log;
    }

    @Override
    protected String getNamePrefix() {
        if (isSSLEnabled()) {
            return "https-" + getSslImplementationShortName()+ "-jss-nio";
        }
        return "http-jss-nio";
    }

    // These methods are temporarly present to replicate the default behaviour provided by tomcat
    public void setSelectorTimeout(long timeout) {
        ((JSSNioEndpoint)getEndpoint()).setSelectorTimeout(timeout);
    }

    public long getSelectorTimeout() {
        return ((JSSNioEndpoint)getEndpoint()).getSelectorTimeout();
    }

    public void setPollerThreadPriority(int threadPriority) {
        ((JSSNioEndpoint)getEndpoint()).setPollerThreadPriority(threadPriority);
    }

    public int getPollerThreadPriority() {
      return ((JSSNioEndpoint)getEndpoint()).getPollerThreadPriority();
    }
}
