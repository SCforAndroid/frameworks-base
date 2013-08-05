/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server.pm;

import android.app.AppGlobals;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageParser;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.Signature;
import android.os.Environment;
import android.os.RemoteException;
import android.util.Slog;
import android.util.Xml;

import com.android.internal.util.XmlUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.Set;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * {@hide}
 * Centralized access to Security Enhanced Android (SE Android) typing
 * judgments.
 * This is very central to the platform's security; please run the unit
 * tests whenever making modifications here:
 * runtest --path=frameworks/base/services/tests/servicestests -j8 -c com.android.server.pm.ContentSecurityManagerTests
 */
public final class ContentSecurityManager {
    private static final String TAG = "ContentSecurityManager";

    public static final boolean DEBUG_POLICY = true;
    private static final boolean DEBUG_POLICY_INSTALL = DEBUG_POLICY || false;

    public enum Access { R, W, RW, USE }

    private Settings mSettings;

    private boolean mPolicyLoaded;
    private AttributeStore mAttributeStore = new AttributeStore();
    private HashMap<String, HashMap<String, Access>> mContentPolicy =
        new HashMap<String, HashMap<String, Access>>();

    private static final File[] POLICY_FILE = {
        new File(Environment.getDataDirectory(), "security/content_permissions.xml"),
        new File(Environment.getRootDirectory(), "etc/security/content_permissions.xml"),
        null
    };

    /*
      Precedence rules:
      (1)signature defined over signature not defined
      (2)provider defined over provider not defined
      (3)package name defined over package name not defined
      (4)export-read defined over export-read not defined
      (5)export-write defined over export-write not defined

      Throughout, there is no distinction between a stanza that
      has more signatures then another. They are considered
      of equal precedence. Same goes for the other selectors.
    */
    Comparator<ContentType> providerComparator = new Comparator<ContentType>() {
        @Override
        public int compare(ContentType a, ContentType b) {

            // defined signatures over not defined signatures
            if (a.mSignatures != null && b.mSignatures == null)
                return -1;
            if (a.mSignatures == null && b.mSignatures != null)
                return 1;

            // defined providers over not defined signatures
            if (a.mProviders != null && b.mProviders == null)
                return -1;
            if (a.mProviders == null && b.mProviders != null)
                return 1;

            // defined packagename over not defined packagename
            if (a.mPackageName != null && b.mPackageName == null)
                return -1;
            if (a.mPackageName == null && b.mPackageName != null)
                return 1;

            // defined export-read over not defined export-read
            if (a.mExportRead != -1 && b.mExportRead == -1)
                return -1;
            if (a.mExportRead == -1 && b.mExportRead != -1)
                return 1;

            // defined export-write over not defined export-write
            if (a.mExportWrite != -1 && b.mExportWrite == -1)
                return -1;
            if (a.mExportWrite == -1 && b.mExportWrite != -1)
                return 1;

            // Equal precedence
            return 0;
        }
    };

    /*
      Precedence rules:
      (1)signature defined over signature not defined
      (2)package name defined over package name not defined
      (3)permission set defined over permission set not defined

      Throughout, there is no distinction between a stanza that
      has more signatures then another. They are considered
      of equal precedence.
    */
    Comparator<PackageType> packageComparator = new Comparator<PackageType>() {
        @Override
        public int compare(PackageType a, PackageType b) {

            // defined signatures over not defined signatures
            if (a.mSignatures != null && b.mSignatures == null)
                return -1;
            if (a.mSignatures == null && b.mSignatures != null)
                return 1;

            // defined package name over not defined package name
            if (a.mPackageName != null && b.mPackageName == null)
                return -1;
            if (a.mPackageName == null && b.mPackageName != null)
                return 1;

            // defined permission set over not defined permission set
            if (a.mPermissionSet != null && b.mPermissionSet == null)
                return -1;
            if (a.mPermissionSet == null && b.mPermissionSet != null)
                return 1;

            // Equal precedence
            return 0;
        }
    };

    private List<PackageType> mPackageTypes = new ArrayList<PackageType>();
    private List<ContentType> mProviderTypes = new ArrayList<ContentType>();

    /**
     * Checks if the policy has been loaded and returns a boolean
     * that representing that state.
     * @return If the policy has been loaded True otherwise False
     */
    public boolean getPolicyLoaded() {
        return mPolicyLoaded;
    }

    /**
     * Sets the boolean that represents if the policy has been loaded or not
     *
     * @param policyLoaded True if the policy should be set to loaded
     * {@hide}
     */
    public void setPolicyLoaded(boolean policyLoaded) {
        mPolicyLoaded = policyLoaded;
    }

    /**
     * Returns an instance of ContentSecurityManager which conforms to a
     * singleton pattern (only one instance of it exists in memory).
     *
     * @return Returns the single instance of ContentSecurityManager in memory.
     */
    public static ContentSecurityManager getInstance() {
        return SingletonHolder.INSTANCE;
    }

    /**
     * Reads the policy for ContentSecurityManager.
     *
     * @return True or false depending on if the policy was successfully read.
     */
    public static boolean readPolicy() {
        return ContentSecurityManager.getInstance().readPolicy(POLICY_FILE);
    }

    /**
     * Reloads policy, is the equivalent of calling readPolicy
     */
    public void reloadPolicy() {
        mPolicyLoaded = readPolicy(POLICY_FILE);
    }

    /**
     * Assigns a type to the package and to all its content providers.
     * {@hide}
     */
    public void setTypes(PackageParser.Package pkg, Settings settings) {

        if (!mPolicyLoaded || mPackageTypes == null) {
            return;
        }

        // We need a way back out to PMS. The PMS constructor hasn't completed
        // at this point and so the getPackageManager() calls aren't ready to
        // return valid objects. And then we need an updated Settings object
        // each time as the info is continuously updated. We are just reading
        // from mSettings never changing internal state.
        mSettings = settings;

        // Assign type to package as a whole
        for (PackageType type : mPackageTypes) {
            if (type.isSatisfied(pkg)) {
                pkg.applicationInfo.cpMac = type.mTypeName;
                Slog.d(TAG, pkg.packageName + " assigned cpMAC=" + type.mTypeName);
                break;
            }
        }

        if (mProviderTypes == null) {
            return;
        }

        // Assign to content providers individually.
        for (PackageParser.Provider provider : pkg.providers) {
            for (ContentType ctype : mProviderTypes) {
                if (ctype.isSatisfied(provider)) {
                    provider.info.providerType = ctype.mTypeName;
                    Slog.d(TAG, provider.info.authority + " assigned providerType="
                           + provider.info.providerType);
                    break;
                }
            }
        }

        return;
    }

    /**
     * Checks policy for access decision between source application and
     * destination provider for R, W, RW, or USE.
     *
     * @param sourceApplication ApplicationInfo of requesting object.
     * @param destinationProvider ProviderInfo for destination Content Provider.
     * @param access Enum that represents the type of access requested.
     * @return Returns True or False if policy allows access.
     */
    public boolean checkPolicy(ApplicationInfo sourceApplication,
            ProviderInfo destinationProvider, int accessVal) {

        ContentSecurityManager.Access access = ContentSecurityManager.Access.values()[accessVal];

        // Is this the correct place for this? If we move this then the
        // following JSON dump will have a npe too.
        if (destinationProvider == null) {
            return false;
        }

        boolean decision = checkPolicyInternal(sourceApplication, destinationProvider, access);
        if (DEBUG_POLICY) {
            printPolicyDecision(sourceApplication, destinationProvider, access, decision);
        }
        return decision;
    }

    private ContentSecurityManager() {
        mPolicyLoaded = readPolicy(POLICY_FILE);
    }

    private static class SingletonHolder {
        public static final ContentSecurityManager INSTANCE = new ContentSecurityManager();
    }

    private void logToDisk(String message) {
        // only log to disk if in debug mode
        if (!DEBUG_POLICY_INSTALL) {
            return;
        }

        String pathToContentLog = "/data/data/content.log";
        try {
            // check if file exists, if not setup logger
            File contentFile = new File(pathToContentLog);
            if(!contentFile.exists()) {
                FileHandler handler = new FileHandler(pathToContentLog, true);
                handler.setFormatter(new LogFormatter());
                Logger.getLogger("ContentSecurityManager").addHandler(handler);
            }

            // write to disk
            Logger.getLogger("ContentSecurityManager").info(message);
        } catch (IOException e) {
            Slog.d(TAG, "Unable to create content.log at: " + pathToContentLog);
            e.printStackTrace();
        }
    }

    /**
     * Making this public helps with unit testing. No need to worry about
     * exposure third party apps as only the system server's copy is the
     * true one.
     */
    public boolean readPolicy(File policyFile) {
        return readPolicy(new File[] { policyFile, null });
    }

    private boolean readPolicy(File[] policyFiles) {

        FileReader policyFile = null;
        int i = 0;
        while (policyFile == null && policyFiles != null && policyFiles[i] != null) {
            try {
                policyFile = new FileReader(policyFiles[i]);
                break;
            } catch (FileNotFoundException e) {
                Slog.d(TAG,"Couldn't find type assignments " + policyFiles[i].getPath());
            }
            i++;
        }

        if (policyFile == null) {
            Slog.e(TAG, "CPMMAC types disabled.");
            return false;
        }

        Slog.d(TAG, "CPMMAC types enabled using file " + policyFiles[i].getPath());
        if (DEBUG_POLICY) Slog.d(TAG, "DEBUG_POLICY=true");
        if (DEBUG_POLICY_INSTALL) Slog.d(TAG, "DEBUG_POLICY_INSTALL=true");

        flushPolicy();

        try {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(policyFile);

            XmlUtils.beginDocument(parser, "policy");
            while (true) {
                XmlUtils.nextElement(parser);
                if (parser.getEventType() == XmlPullParser.END_DOCUMENT) {
                    break;
                }

                String tagName = parser.getName();

                if ("type".equalsIgnoreCase(tagName)) {
                    String name = parser.getAttributeValue(null, "name");
                    if (name == null) {
                        Slog.w(TAG, "<type> without name at "
                                + parser.getPositionDescription());
                        XmlUtils.skipCurrentTag(parser);
                        continue;
                    }
                    // component attribute will allow us to potentially distinguish
                    // between service, activity, receiver, and provider (think class).
                    String component = parser.getAttributeValue(null, "component");

                    BaseType type = readPolicyForType(parser, name, component);
                    if (component != null && component.equals("package")) {
                        mPackageTypes.add((PackageType)type);
                    } else {
                        mProviderTypes.add((ContentType)type);
                    }
                    if (DEBUG_POLICY_INSTALL) {
                        StringBuilder info = new StringBuilder();
                        info.append("Added type " + type.mTypeName);
                        info.append(" => {");
                        info.append("pkg=" + type.mPackageName + ", ");
                        info.append("sigs=" + type.mSignatures + ", ");
                        if (type instanceof ContentType) {
                            info.append("providers=" + ((ContentType)type).mProviders + ", ");
                            info.append("export-read=" + ((ContentType)type).mExportRead + ", ");
                            info.append("export-write=" + ((ContentType)type).mExportWrite + ", ");
                        } else if (type instanceof PackageType) {
                            info.append("perms=" + ((PackageType)type).mPermissionSet + ", ");
                        }
                        info.append("}");
                        Slog.d(TAG, info.toString());
                    }
                } else if ("attributes".equals(tagName)) {
                    parseAttributes(parser);
                } else if ("allow-content".equals(tagName)) {
                    parseAllowContent(parser);
                } else {
                    XmlUtils.skipCurrentTag(parser);
                    continue;
                }
            }
        } catch (XmlPullParserException e) {
            Slog.w(TAG, "Got execption parsing ", e);
        } catch (IOException e) {
            Slog.w(TAG, "Got execption parsing ", e);
        }
        try {
            policyFile.close();
        } catch (IOException e) {
            //omit
        }
        Collections.sort(mPackageTypes, packageComparator);
        mPackageTypes = Collections.unmodifiableList(mPackageTypes);
        Collections.sort(mProviderTypes, providerComparator);
        mProviderTypes = Collections.unmodifiableList(mProviderTypes);
        Slog.d(TAG, "Loaded " + mPackageTypes.size() + " package type rules");
        Slog.d(TAG, "Loaded " + mProviderTypes.size() + " provider type rules");
        if (DEBUG_POLICY) {
            for (ContentType ctype : mProviderTypes) {
                Slog.d(TAG, ctype.toString());
            }
        }
        return true;
    }

    private void flushPolicy() {
        this.mPackageTypes   = new ArrayList<PackageType>();
        this.mProviderTypes  = new ArrayList<ContentType>();
        this.mAttributeStore = new AttributeStore();
        this.mContentPolicy  = new HashMap<String, HashMap<String, Access>>();
    }

    private void parseAttributes(XmlPullParser parser) throws
        IOException, XmlPullParserException {
        int type;
        int outerDepth = parser.getDepth();
        while ((type=parser.next()) != XmlPullParser.END_DOCUMENT
               && (type != XmlPullParser.END_TAG || parser.getDepth() > outerDepth)) {
            if (type == XmlPullParser.END_TAG || type == XmlPullParser.TEXT) {
                continue;
            }

            String tagName = parser.getName();
            if ("attribute".equals(tagName)) {
                String attrName = parser.getAttributeValue(null, "name");
                if (attrName != null) {
                    HashSet<String> typeSet = parseTypes(parser);
                    this.mAttributeStore.put(attrName, typeSet);
                } else {
                    Slog.d(TAG, "<attribute> without value(s) at " + parser.getPositionDescription());
                }
            }
        }
    }

    private HashSet<String> parseTypes(XmlPullParser parser) throws
        IOException, XmlPullParserException {
        int type;
        HashSet<String> typeSet = new HashSet<String>();
        int outerDepth = parser.getDepth();
        while ((type=parser.next()) != XmlPullParser.END_DOCUMENT &&
               (type != XmlPullParser.END_TAG || parser.getDepth() > outerDepth)) {
            if (type == XmlPullParser.END_TAG || type == XmlPullParser.TEXT) {
                continue;
            }

            String tagName = parser.getName();
            if ("type".equals(tagName)) {
                String typeName = parser.getAttributeValue(null, "name");
                if (typeName != null) {
                    typeSet.add(typeName);
                } else {
                    Slog.d(TAG, "<type> without value(s) at " + parser.getPositionDescription());
                }
            }
        }
        return typeSet;
    }

    private void parseAllowContent(XmlPullParser parser) throws
        IOException, XmlPullParserException {
        int type;
        int outerDepth = parser.getDepth();
        while ((type=parser.next()) != XmlPullParser.END_DOCUMENT &&
               (type != XmlPullParser.END_TAG || parser.getDepth() > outerDepth)) {
            if (type == XmlPullParser.END_TAG || type == XmlPullParser.TEXT) {
                continue;
            }

            String tagName = parser.getName();
            if ("allow".equals(tagName)) {
                String srcValue = parser.getAttributeValue(null, "source");
                String dstValue = parser.getAttributeValue(null, "destination");
                String prmValue = parser.getAttributeValue(null, "permission");

                if (srcValue != null && dstValue != null && prmValue != null) {

                    if (!this.mAttributeStore.contains(srcValue)) {
                        this.mAttributeStore.put(srcValue, srcValue);
                    }
                    if (!this.mAttributeStore.contains(dstValue)) {
                        this.mAttributeStore.put(dstValue, dstValue);
                    }

                    HashSet<String> srcSet = this.mAttributeStore.get(srcValue);
                    HashSet<String> dstSet = this.mAttributeStore.get(dstValue);

                    AttributeStore excludeStore = parseExclude(parser);
                    HashSet<String> srcExclude = excludeStore.get("source");
                    HashSet<String> dstExclude = excludeStore.get("destination");
                    if (srcExclude != null) {
                        srcSet.removeAll(srcExclude);
                    }
                    if (dstExclude != null) {
                        dstSet.removeAll(dstExclude);
                    }

                    Access accessPerm;
                    try {
                        String[] p = prmValue.toUpperCase().split(";");
                        if (p.length == 2) {
                            accessPerm = Access.valueOf(p[1]);
                        } else {
                            accessPerm = Access.valueOf(p[0]);
                        }
                    } catch (IllegalArgumentException e) {
                        Slog.d(TAG, "permission tag unparseable at " +
                               parser.getPositionDescription());
                        continue;
                    }

                    for (String src : srcSet) {
                        for (String dst : dstSet) {
                            addAllowRule(src, dst, accessPerm);
                            Slog.d(TAG, "allow-content src="+ src + " dst=" + dst +
                                   " accessPerm=" + accessPerm);
                        }
                    }
                } else {
                    Slog.d(TAG, "<allow-content> without value(s) at " +
                           parser.getPositionDescription());
                }
            }
        }
    }

    private AttributeStore parseExclude(XmlPullParser parser) throws
        IOException, XmlPullParserException {
        int type;
        AttributeStore excludeAttributeStore = new AttributeStore();
        int outerDepth = parser.getDepth();
        while ((type=parser.next()) != XmlPullParser.END_DOCUMENT &&
               (type != XmlPullParser.END_TAG || parser.getDepth() > outerDepth)) {
            if (type == XmlPullParser.END_TAG || type == XmlPullParser.TEXT) {
                continue;
            }

            String tagName = parser.getName();
            if ("exclude".equals(tagName)) {
                String srcValue = parser.getAttributeValue(null, "source");
                String dstValue = parser.getAttributeValue(null, "destination");

                if (srcValue != null && dstValue != null) {
                    Slog.d(TAG, "<exclude> with two value(s) at " + parser.getPositionDescription());
                    continue;
                }
                if (srcValue == null && dstValue == null) {
                    Slog.d(TAG, "<exclude> without value(s) at " + parser.getPositionDescription());
                    continue;
                }

                if (srcValue != null) {
                    excludeAttributeStore.put("source", srcValue);
                    continue;
                }
                if (dstValue != null) {
                    excludeAttributeStore.put("destination", dstValue);
                    continue;
                }
            }
        }
        return excludeAttributeStore;
    }

    private BaseType readPolicyForType(XmlPullParser parser,
        String typeName, String kind) throws XmlPullParserException, IOException {

        String packageName = null;
        String exportRead = null;
        String exportWrite = null;
        Set<String> permissions = new HashSet<String>();
        Set<String> providers = new HashSet<String>();
        Set<Signature> signatures = new HashSet<Signature>();

        int type;
        int outerDepth = parser.getDepth();
        while ((type=parser.next()) != XmlPullParser.END_DOCUMENT
                && (type != XmlPullParser.END_TAG
                    || parser.getDepth() > outerDepth)) {
            if (type == XmlPullParser.END_TAG
                || type == XmlPullParser.TEXT) {
                continue;
            }

            String tagName = parser.getName();
            if ("package".equals(tagName)) {
                String value = parser.getAttributeValue(null, "value");
                packageName = value;
            } else if ("signature".equals(tagName)) {
                String value = parser.getAttributeValue(null, "value");
                Signature sig = new Signature(value);
                signatures.add(sig);
            } else if ("permission".equals(tagName)) {
                String value = parser.getAttributeValue(null, "value");
                permissions.add(value);
            } else if ("provider".equals(tagName)) {
                String value = parser.getAttributeValue(null, "value");
                providers.add(value);
            } else if ("export-read".equals(tagName)) {
                String level = parser.getAttributeValue(null, "value");
                exportRead = level;
            } else if ("export-write".equals(tagName)) {
                String level = parser.getAttributeValue(null, "value");
                exportWrite = level;
            }

            XmlUtils.skipCurrentTag(parser);
        }

        if (permissions.size() == 0) permissions = null;
        if (signatures.size() == 0) signatures = null;
        if (providers.size() == 0) providers = null;

        if (kind != null && kind.equals("package")) {
            return new PackageType(typeName, packageName, permissions, signatures);
        } else {
            return new ContentType(typeName, packageName, signatures,
                                   providers, exportRead, exportWrite);
        }
    }

    private boolean addAllowRule(String srcType, String dstType, Access access) {

        boolean hasPackageRules = this.mContentPolicy.containsKey(srcType);
        if (hasPackageRules) {
            HashMap<String, Access> packageRules = this.mContentPolicy.get(srcType);
            boolean hasRule = packageRules.containsKey(dstType);
            if (hasRule) {
                return false;
            }
            packageRules.put(dstType, access);
        } else {
            HashMap<String, Access> packageRules = new HashMap<String, Access>(1);
            packageRules.put(dstType, access);
            this.mContentPolicy.put(srcType, packageRules);
        }

        return true;
    }

    private boolean checkPolicyInternal(ApplicationInfo sourceApplication,
            ProviderInfo destinationProvider, Access reqAccess) {

        String srcType = sourceApplication.cpMac;
        String dstType = destinationProvider.providerType;

        if (DEBUG_POLICY_INSTALL) {
            Slog.d(TAG, "Checking srcType=" + srcType + ", dstType=" + dstType +
                ", perm=" + reqAccess + ", authString=" + destinationProvider.authority);
        }

        if (srcType == null || dstType == null) {
            return false;
        }

        boolean hasPackageRules = this.mContentPolicy.containsKey(srcType);
        if (!hasPackageRules) {
            return false;
        }

        HashMap<String, Access> packageRules = this.mContentPolicy.get(srcType);
        boolean hasRule = packageRules.containsKey(dstType);
        if (!hasRule) {
            return false;
        }


        /*
         * The below matrix displays the access rules for Content Providers.
         * The USE permission is used to obtain a handle to the Content
         * Provider, but does not provide and read or write capability. Read,
         * Write, or Read-Write imply you have the USE permission, and allow
         * you to perform those respective actions.
         *
         *
         *                       hasAccess
         *
         *                  | USE |  R  |  W  |  RW
         *            -------------------------------
         *             USE  |     |     |     |
         *            -------------------------------
         *             R    |  x  |     |  x  |
         * reqAccess  -------------------------------
         *             W    |  x  |  x  |     |
         *            -------------------------------
         *             RW   |  x  |  x  |  x  |
         *            -------------------------------
         *
         *                      Deny Access
         */

        Access hasAccess = packageRules.get(dstType);
        if (DEBUG_POLICY_INSTALL) {
            Slog.d(TAG, "(" + srcType + ", " + dstType + ") " +
                "Policy allows access: " + hasAccess + ", Requesting: " + reqAccess);
        }

        if (hasAccess == Access.USE) {
            if (reqAccess == Access.R || reqAccess == Access.W || reqAccess == Access.RW) {
                return false;
            }
        }
        if (hasAccess == Access.R) {
            if (reqAccess == Access.W || reqAccess == Access.RW) {
                return false;
            }
        }
        if (hasAccess == Access.W) {
            if (reqAccess == Access.R || reqAccess == Access.RW) {
                return false;
            }
        }

        return true;
    }

    private void printPolicyDecision(ApplicationInfo sourceApplication,
            ProviderInfo destinationProvider, Access access, boolean decision) {

        ApplicationInfo destinationApplication = destinationProvider.applicationInfo;
        String srcType = sourceApplication.cpMac;
        String dstType = destinationProvider.providerType;
        String srcPackage = sourceApplication.packageName;
        String dstPackage = destinationApplication.packageName;
        String srcPublicName = sourceApplication.name;
        String dstPublicName = destinationProvider.name;
        String srcUid = Integer.toString(sourceApplication.uid);
        String dstUid = Integer.toString(destinationApplication.uid);
        String srcProcessName = sourceApplication.processName;
        String dstProcessName = destinationApplication.processName;
        String dstAuth = destinationProvider.authority;

        JSONObject jsonMessage = new JSONObject();
        JSONObject destinationObject = new JSONObject();
        JSONObject sourceObject = new JSONObject();

        try {
            sourceObject.put("uid", srcUid );
            sourceObject.put("process name", srcProcessName);
            sourceObject.put("public name", srcPublicName);
            sourceObject.put("package", srcPackage);
            sourceObject.put("type", srcType);

            destinationObject.put("uid", dstUid);
            destinationObject.put("process name", dstPublicName);
            destinationObject.put("type", dstType);
            destinationObject.put("package", dstPackage);
            destinationObject.put("public name", dstPublicName);
            destinationObject.put("authority", dstAuth);

            jsonMessage.put("access", access);
            jsonMessage.put("decision", Boolean.toString(decision));
            jsonMessage.put("source", sourceObject);
            jsonMessage.put("destination", destinationObject);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        Slog.d(TAG, jsonMessage.toString());
        logToDisk(jsonMessage.toString());
    }

    public String toString() {
        return "attribute store: " + this.mAttributeStore.toString() + " ### " +
            "content policy: " + this.mContentPolicy.toString()      + " ### " +
            "package types: " + this.mPackageTypes.toString()        + " ### " +
            "policy loaded: " + this.mPolicyLoaded;
    }

    private class AttributeStore
    {
        private HashMap<String, HashSet<String>> attributeMap;

        public AttributeStore() {
            this.attributeMap = new HashMap<String, HashSet<String>>();
        }

        public HashSet<String> get(String key) {
            return this.attributeMap.get(key);
        }

        public void put(String key, String value) {
            HashSet<String> types;

            boolean containsKey = this.attributeMap.containsKey(key);
            if (containsKey) {
                types = this.attributeMap.get(key);
                types.add(value);
            } else {
                types = new HashSet<String>(1);
                types.add(value);
            }
            this.attributeMap.put(key, types);
        }

        public void put(String key, HashSet<String> values) {
            HashSet<String> types;

            boolean containsKey = this.attributeMap.containsKey(key);
            if (containsKey) {
                types = this.attributeMap.get(key);
                types.addAll(values);
            } else {
                types = new HashSet<String>(values.size());
                types.addAll(values);
            }
            this.attributeMap.put(key, types);
        }

        public boolean contains(String key) {
            return this.attributeMap.containsKey(key);
        }

        public void remove(String key) {
            boolean containsKey = this.attributeMap.containsKey(key);
            if (containsKey) {
                this.attributeMap.remove(key);
            }
        }

        public void remove(HashSet<String> keys) {
            for (String key : keys) {
                boolean containsKey = this.attributeMap.containsKey(key);
                if (containsKey) {
                    this.attributeMap.remove(key);
                }
            }
        }

        public void clear() {
            this.attributeMap.clear();
        }

        public String toString() {
            return this.attributeMap.toString();
        }
    }

    // Map string to a permission level int.
    private int protectionLevelMap(String levelAsString) {
        if (levelAsString == null) {
            return -1;
        }

        if (levelAsString.equals("normal")) {
            return PermissionInfo.PROTECTION_NORMAL;
        } else if (levelAsString.equals("dangerous")) {
            return PermissionInfo.PROTECTION_DANGEROUS;
        } else if (levelAsString.equals("signature")) {
            return PermissionInfo.PROTECTION_SIGNATURE;
        } else if (levelAsString.equals("signatureOrSystem")) {
            return PermissionInfo.PROTECTION_SIGNATURE_OR_SYSTEM;
        } else {
            return -1;
        }
    }

    // Our 'order' is: normal < dangerous < signature|system < signature
    // where '<' means more restrictive than LHS but less restrictive than
    // RHS. normal = 0, dangerous = 1, sig|system = 3, sig = 2
    // since the development perm is 0x20 lets just return false for now.
    private boolean comparePerms(int currentLevel, int policyPerm) {
        if (policyPerm == -1) {
            return false;
        }

        switch (currentLevel) {
          case 0:
              return policyPerm <= 0;
          case 1:
              return policyPerm <= 1;
          case 2:
              return policyPerm <= 3;
          case 3:
              return policyPerm == 3 || policyPerm <= 1;
          default:
              return false;
        }
    }

    private class BaseType {

        final String mTypeName;
        final String mPackageName;
        final Set<Signature> mSignatures;

        private BaseType(String typeName, String packageName, Set<Signature> signatures) {
            mTypeName = typeName;
            mPackageName = packageName;

            if (signatures != null) {
                Set<Signature> temp = new HashSet<Signature>(signatures.size());
                temp.addAll(signatures);
                mSignatures = Collections.unmodifiableSet(temp);
            } else {
                mSignatures = null;
            }
        }

        /**
         * {@hide}
         */
        public boolean isSatisfied(PackageParser.Package pkg) {
            boolean ret = true;

            if (ret && null != mPackageName) {
                String pkgName = pkg.packageName;
                ret = ret && pkgName.equals(mPackageName);
            }

            if (ret && null != mSignatures) {
                Set<Signature> pkgSigs = new HashSet<Signature>(pkg.mSignatures.length);
                for (Signature sig : pkg.mSignatures) {
                    pkgSigs.add(sig);
                }
                for (Signature sig : mSignatures) {
                    ret = ret && pkgSigs.contains(sig);
                    if (!ret) break;
                }
            }

            return ret;
        }

    }

    // inner class used to define a type assignment for an entire package
    private class PackageType extends BaseType {

        // All conditions below must be satisfied for a type to be assigned to a package. If a
        // condition is null, that condition is not checked.

        // If package has a superset of this set of permissions, it is assigned this type.
        final Set<String> mPermissionSet;

        private PackageType(String typeName, String packageName,
                Set<String> permissionSet, Set<Signature> signatures) {
            super(typeName, packageName, signatures);

            if (permissionSet != null) {
                Set<String> temp = new HashSet<String>(permissionSet.size());
                temp.addAll(permissionSet);
                mPermissionSet = Collections.unmodifiableSet(temp);
            } else {
                mPermissionSet = null;
            }
        }

        /**
         * {@hide}
         */
        public boolean isSatisfied(PackageParser.Package pkg) {
            boolean ret = true;

            if (!super.isSatisfied(pkg)) {
                return false;
            }

            if (ret && null != mPermissionSet) {
                //XXX Is requestedPermissions the right object to use here?
                Set<String> pkgPerms = new HashSet<String>(pkg.requestedPermissions.size());
                pkgPerms.addAll(pkg.requestedPermissions);
                for (String perm : mPermissionSet) {
                    ret = ret && pkgPerms.contains(perm);
                    if (!ret) break;
                }
            }

            return ret;
        }
    }


    // inner class used to assign content provider types
    private class ContentType extends BaseType {

        // If auth string is contained in this Set then assigned this type.
        final Set<String> mProviders;
        // Holds the protection level of the perm required.
        final int mExportRead;
        final int mExportWrite;

        private ContentType(String typeName, String packageName,
                            Set<Signature> signatures, Set<String> providers,
                            String read, String write) {
            super(typeName, packageName, signatures);

            if (providers != null) {
                Set<String> temp = new HashSet<String>(providers.size());
                temp.addAll(providers);
                mProviders = Collections.unmodifiableSet(temp);
            } else {
                mProviders = null;
            }

            mExportRead = protectionLevelMap(read);
            mExportWrite = protectionLevelMap(write);

        }

        public boolean isSatisfied(PackageParser.Provider provider) {

            // First check if the sig and package selectors match.
            if (!super.isSatisfied(provider.owner)) {
                return false;
            }

            // Watch out for auth string that use ';' to multi-name the provider.
            // contacts;com.android.contacts is one of these buggers.
            // In this case we want to make sure both are checked against
            // the same type stanza. Policy wouldn't make sense to include
            // only one of the two names in a type stanza.
            if (null != mProviders) {
                Set<String> auth = new HashSet<String>();
                Collections.addAll(auth, provider.info.authority.split(";"));
                if (!mProviders.containsAll(auth)) {
                    return false;
                }
            }

            // Check exported and read/write perms
            boolean exported = provider.info.exported;
            if (mExportRead >= 0) {
                if (!exported) {
                    return false;
                }
                String readPerm = provider.info.readPermission;
                int level = -1;
                final BasePermission p = mSettings.mPermissions.get(readPerm);
                if (p != null) {
                    level = p.protectionLevel;
                }
                if (!comparePerms(level, mExportRead)) {
                    return false;
                }
            }

            if (mExportWrite >= 0) {
                if (!exported) {
                    return false;
                }
                String writePerm = provider.info.writePermission;
                int level = -1;
                final BasePermission p = mSettings.mPermissions.get(writePerm);
                if (p != null) {
                    level = p.protectionLevel;
                }
                if (!comparePerms(level, mExportWrite)) {
                    return false;
                }
            }

            return true;
        }

        @Override
        public String toString() {
            StringBuilder result = new StringBuilder();
            result.append("type=["+mTypeName+"]");
            result.append(" packagename=["+mPackageName+"]");
            if (mSignatures != null) {
                result.append(" signatures="+mSignatures);
            }
            if (mProviders != null) {
                result.append(" auth_string="+mProviders);
            }
            result.append(" export-read=["+mExportRead+"]");
            result.append(" export-write=["+mExportWrite+"]");
            return result.toString();
        }
    }

    private final class LogFormatter extends Formatter {

        private final String LINE_SEPARATOR = System.getProperty("line.separator");

        @Override
        public String format(LogRecord record) {
            StringBuilder sb = new StringBuilder();

            sb.append(formatMessage(record)).append(LINE_SEPARATOR);

            if (record.getThrown() != null) {
                try {
                    StringWriter sw = new StringWriter();
                    PrintWriter pw = new PrintWriter(sw);
                    record.getThrown().printStackTrace(pw);
                    pw.close();
                    sb.append(sw.toString());
                } catch (Exception ex) {
                    // ignore
                }
            }

            return sb.toString();
        }
    }
}
