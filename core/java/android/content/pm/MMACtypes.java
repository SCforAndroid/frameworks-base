/*
 * Copyright (C) 2012 The Android Open Source Project
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

package android.content.pm;

import android.os.Environment;
import android.os.SystemProperties;
import android.util.Slog;
import android.util.Xml;

import com.android.internal.util.XmlUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

/**
 * Centralized access to typing judgments.
 * {@hide}
 */
public final class MMACtypes {
    private static final String TAG = "MMACtypes";

    public  static final boolean DEBUG_POLICY = true;
    private static final boolean DEBUG_POLICY_INSTALL = DEBUG_POLICY || false;

    private static final File[] POLICY_FILE = {
        new File(Environment.getDataDirectory(), "security/mmac_types.xml"),
        new File(Environment.getRootDirectory(), "etc/security/mmac_types.xml"),
        null
    };

    private Set<PackageType> mPackageTypes;
    private boolean mPolicyLoaded;

    // inner class used to define a type assignment
    private class PackageType {
        final String mTypeName;

        // All conditions below must be satisfied for a type to be assigned to a package. If a
        // condition is null, that condition is not checked.

        // If package is named this, it is assigned this type.
        final String mPackageName;
        // If package has a superset of this set of permissions, it is assigned this type.
        final Set<String> mPermissionSet;
        // If package is signed by all of these signatures, it is assigned this type
        final Set<Signature> mSignatures;

        public PackageType(String typeName, String packageName,
                Set<String> permissionSet, Set<Signature> signatures) {
            mTypeName = typeName;
            mPackageName = packageName;

            if (permissionSet != null) {
                Set<String> temp = new HashSet<String>(permissionSet.size());
                temp.addAll(permissionSet);
                mPermissionSet = Collections.unmodifiableSet(temp);
            } else {
                mPermissionSet = null;
            }

            if (signatures != null) {
                Set<Signature> temp = new HashSet<Signature>(signatures.size());
                temp.addAll(signatures);
                mSignatures = Collections.unmodifiableSet(temp);
            } else {
                mSignatures = null;
            }
        }

        public boolean isSatisfied(PackageParser.Package pkg) {
            boolean ret = true;

            if (ret && null != mPackageName) {
                String pkgName = pkg.packageName;
                ret = ret && pkgName.equals(mPackageName);
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

    private MMACtypes() {
        mPolicyLoaded = readPolicy(POLICY_FILE);
    }

    private static class SingletonHolder {
        public static final MMACtypes INSTANCE = new MMACtypes();
    }

    private boolean readPolicy(File policyFile) {
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
            Slog.e(TAG, "MMAC types disabled.");
            return false;
        }

        Slog.d(TAG, "MMAC types enabled using file " + policyFiles[i].getPath());
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

                    PackageType type = readPolicyForType(parser, name);
                    mPackageTypes.add(type);
                    if (DEBUG_POLICY_INSTALL) {
                        Slog.d(TAG, "Added type " + type.mTypeName
                                + " => {"
                                + "pkg=" + type.mPackageName + ", "
                                + "perms=" + type.mPermissionSet + ", "
                                + "sigs=" + type.mSignatures
                                + "}");
                    }

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
        mPackageTypes = Collections.unmodifiableSet(mPackageTypes);
        Slog.d(TAG, "Loaded " + mPackageTypes.size() + " type rules");
        return true;
    }

    private PackageType readPolicyForType(XmlPullParser parser,
            String typeName) throws XmlPullParserException, IOException {

        String packageName = null;
        Set<String> permissions = new HashSet<String>();
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
            }

            XmlUtils.skipCurrentTag(parser);
        }

        if (permissions.size() == 0) permissions = null;
        if (signatures.size() == 0) signatures = null;

        return new PackageType(typeName, packageName, permissions, signatures);
    }

    private void flushPolicy() {
        mPackageTypes = new HashSet<PackageType>();
    }


    public boolean getPolicyLoaded() {
        return mPolicyLoaded;
    }

    public void setPolicyLoaded(boolean policyLoaded) {
        mPolicyLoaded = policyLoaded;
    }

    /**
     * Returns a shared instance which can be used to query
     * for typing judgments.
     * @param  none
     * @return shared instance of IntentMAC.
     */
    public static MMACtypes getInstance() {
        return SingletonHolder.INSTANCE;
    }

    public static boolean readPolicy() {
        return MMACtypes.getInstance().readPolicy(POLICY_FILE);
    }

    /**
     * Forces a reloading of the policy file.
     * XXX CAN'T BE RELOADED. MUST RESTART PHONE TO RELOAD! Not sure how to reassign types over
     * all packages if a new policy comes in.
     * @param  none
     * @return none
     */
    public void reloadPolicy() {
        mPolicyLoaded = readPolicy(POLICY_FILE);
    }

    public Set<String> getTypes(PackageParser.Package pkg) {

        if (!mPolicyLoaded || mPackageTypes == null) {
            return Collections.emptySet();
        }

        Set<String> types = new HashSet<String>();

        // Adds a type that is the package name with a period added to the end
        boolean applyNameType = SystemProperties.getBoolean("persist.mac_applyNameTypes", false);
        if (applyNameType) {
            types.add(pkg.packageName);
        }

        // Adds a type that is the permission string with a period added to the end
        boolean applyPermTypes = SystemProperties.getBoolean("persist.mac_applyPermTypes", false);
        if (applyPermTypes) {
            for (String perm : pkg.requestedPermissions) {
                types.add(perm);
            }
        }

        for (PackageType type : mPackageTypes) {
            if (type.isSatisfied(pkg)) {
                types.add(type.mTypeName);
            }
        }

        return Collections.unmodifiableSet(types);
    }
}
