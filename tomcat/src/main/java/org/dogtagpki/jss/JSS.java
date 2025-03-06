//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.jss;

import org.dogtagpki.jss.tomcat.TomcatJSS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class provides a mechanism to initialize JSS in Tomcat.
 * It inherits from TomcatJSS for backward compatibility.
 */
public class JSS extends TomcatJSS {

    public static final Logger logger = LoggerFactory.getLogger(JSS.class);

    public static final JSS INSTANCE = new JSS();

    public static JSS getInstance() { return INSTANCE; }
}
