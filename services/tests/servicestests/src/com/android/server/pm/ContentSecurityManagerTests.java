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

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageParser;
import android.content.pm.PackageParser.Permission;
import android.content.pm.ProviderInfo;
import android.content.res.Resources;
import android.content.res.Resources.NotFoundException;
import android.net.Uri;
import android.os.FileUtils;
import android.test.AndroidTestCase;
import android.test.suitebuilder.annotation.LargeTest;
import android.util.DisplayMetrics;
import android.util.Log;

import com.android.server.pm.ContentSecurityManager;

import com.android.frameworks.servicestests.R;

import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.util.ArrayList;

/** Test {@link ContentSecurityManager} functionality. */
public class ContentSecurityManagerTests extends AndroidTestCase {

    private static final String TAG = "ContentSecurityManagerTests";

    private static File MAC_INSTALL_TMP;
    private static File APK_SRC_INSTALL_TMP;
    private static File APK_DST_INSTALL_TMP;
    private static final String MAC_INSTALL_TMP_NAME = "cp_policy";
    private static final String APK_SRC_INSTALL_TMP_NAME = "install_src.apk";
    private static final String APK_DST_INSTALL_TMP_NAME = "install_dst.apk";

    private Settings mSettings;

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        // Need a tmp file to hold the various provider policy files.
        File filesDir = mContext.getFilesDir();
        MAC_INSTALL_TMP = new File(filesDir, MAC_INSTALL_TMP_NAME);
        assertNotNull(MAC_INSTALL_TMP);

        // Need a tmp file to hold the src apk
        APK_SRC_INSTALL_TMP = new File(filesDir, APK_SRC_INSTALL_TMP_NAME);
        assertNotNull(APK_SRC_INSTALL_TMP);

        // Need a tmp file to hold the dst apk
        APK_DST_INSTALL_TMP = new File(filesDir, APK_DST_INSTALL_TMP_NAME);
        assertNotNull(APK_DST_INSTALL_TMP);

        // Need a Settings object for permission related stuff.
        mSettings = new Settings(mContext);
        assertNotNull(mSettings);
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        // Just in case still around
        MAC_INSTALL_TMP.delete();
        APK_SRC_INSTALL_TMP.delete();
        APK_DST_INSTALL_TMP.delete();

        // Reload the original policy
        ContentSecurityManager.readPolicy();
    }

    void failStr(String errMsg) {
        Log.w(TAG, "errMsg="+errMsg);
        fail(errMsg);
    }

    void failStr(Exception e) {
        failStr(e.getMessage());
    }

    private PackageParser.Package parsePackage(Uri packageURI) {
        final String archiveFilePath = packageURI.getPath();
        PackageParser packageParser = new PackageParser(archiveFilePath);
        File sourceFile = new File(archiveFilePath);
        DisplayMetrics metrics = new DisplayMetrics();
        metrics.setToDefaults();
        PackageParser.Package pkg = packageParser.parsePackage(sourceFile,
                                                               archiveFilePath,
                                                               metrics, 0);
        assertNotNull(pkg);
        assertTrue(packageParser.collectCertificates(pkg,0));

        // Load up the defined permissions if they exist for the package.
        for (Permission perm : pkg.permissions) {
            BasePermission bp = mSettings.mPermissions.get(perm.info.name);
            if (bp == null) {
                bp = new BasePermission(perm.info.name, null, BasePermission.TYPE_BUILTIN);
                bp.protectionLevel = perm.info.protectionLevel;
                mSettings.mPermissions.put(perm.info.name, bp);
                assertNotNull(mSettings.mPermissions.get(perm.info.name));
            }
        }

        packageParser = null;
        return pkg;
    }

    Uri getResourceURI(int fileResId, File outFile) {
        Resources res = mContext.getResources();
        InputStream is = null;
        try {
            is = res.openRawResource(fileResId);
        } catch (NotFoundException e) {
            failStr("Failed to load resource with id: " + fileResId);
        }
        assertNotNull(is);
        FileUtils.setPermissions(outFile.getPath(),
                                 FileUtils.S_IRWXU | FileUtils.S_IRWXG | FileUtils.S_IRWXO,
                                 -1, -1);
        assertTrue(FileUtils.copyToFile(is, outFile));
        FileUtils.setPermissions(outFile.getPath(),
                                 FileUtils.S_IRWXU | FileUtils.S_IRWXG | FileUtils.S_IRWXO,
                                 -1, -1);
        return Uri.fromFile(outFile);
    }

    /**
     * Tests the typing assignments based on policy.
     * Takes the policy xml file as a resource, the apk as a resource,
     * the expected providerType string. We mock a package install here
     * by calling parsePackage.
     */
    void checkCpMMAC(int policyRes, int apkRes, String expectedType) {

        // grab policy file
        Uri policyURI = getResourceURI(policyRes, MAC_INSTALL_TMP);
        assertNotNull(policyURI);
        // parse the policy file
        boolean ret = ContentSecurityManager.getInstance().readPolicy(new File(policyURI.getPath()));
        assertTrue(ret);
        // grab the apk
        Uri apkURI = getResourceURI(apkRes, APK_SRC_INSTALL_TMP);
        assertNotNull(apkURI);
        // "install" the apk
        PackageParser.Package pkg = parsePackage(apkURI);
        assertNotNull(pkg);
        assertNotNull(pkg.packageName);
        // assign the types to the providers
        ContentSecurityManager.getInstance().setTypes(pkg, mSettings);
        // Check for the correct provider type.
        // Given the limited nature of the arguments passed to
        // this function, we are checking only one provider
        // is requested by the AndroidManifest.xml.
        ArrayList<PackageParser.Provider> providers = pkg.providers;
        assertNotNull(providers);
        assertEquals(providers.size(), 1);
        ProviderInfo provider = providers.get(0).info;
        assertNotNull(provider);
        String providerType = provider.providerType;
        assertNotNull(providerType);
        assertEquals(expectedType, providerType);

        // delete policy and apk
        MAC_INSTALL_TMP.delete();
        APK_SRC_INSTALL_TMP.delete();
    }

    /**
     * Tests the allow rules based on the type assigments and access rules.
     * Takes a policy xml file as resource, then a source and destination
     * apk, access requested, expected result. We then mock a package
     * install then call to checkPolicy within the ContentSecurityManager
     * to verify the results.
     */
    void checkProviderPolicy(int policyRes, int sourceApk, int destApk,
            ContentSecurityManager.Access access, boolean expectedResult) {
        // grab policy file
        Uri policyURI = getResourceURI(policyRes, MAC_INSTALL_TMP);
        assertNotNull(policyURI);
        // parse the policy file
        boolean ret = ContentSecurityManager.getInstance().readPolicy(new File(policyURI.getPath()));
        assertTrue(ret);

        // get, install, assign types, and extract application info
        // for the source apk
        Uri sourceApkURI = getResourceURI(sourceApk, APK_SRC_INSTALL_TMP);
        assertNotNull(sourceApkURI);
        PackageParser.Package sourcePkg = parsePackage(sourceApkURI);
        assertNotNull(sourcePkg);
        assertNotNull(sourcePkg.packageName);
        ContentSecurityManager.getInstance().setTypes(sourcePkg, mSettings);
        ApplicationInfo sourceApplicationInfo = sourcePkg.applicationInfo;
        assertNotNull(sourceApplicationInfo);

        // get, install, assign types, and extract application info
        // for the destination apk
        Uri destApkURI = getResourceURI(destApk, APK_DST_INSTALL_TMP);
        assertNotNull(destApkURI);
        PackageParser.Package destPkg = parsePackage(destApkURI);
        assertNotNull(destPkg);
        assertNotNull(destPkg.packageName);
        ContentSecurityManager.getInstance().setTypes(destPkg, mSettings);
        ArrayList<PackageParser.Provider> destProviders = destPkg.providers;
        assertNotNull(destProviders);
        assertEquals(destProviders.size(), 1);
        ProviderInfo destinationProvider = destProviders.get(0).info;
        assertNotNull(destinationProvider);

        // call into the content security manager to check policy
        boolean csmDecision = ContentSecurityManager.getInstance().checkPolicy(
            sourceApplicationInfo, destinationProvider, access.ordinal());
        assertEquals(expectedResult, csmDecision);

        // delete policy and apk
        MAC_INSTALL_TMP.delete();
        APK_SRC_INSTALL_TMP.delete();
        APK_DST_INSTALL_TMP.delete();
    }

    /*
     * Requested policy file doesn't exist.
     */
    @LargeTest
    public void testINSTALL_POLICY_BADPATH() {
        boolean ret = ContentSecurityManager.getInstance().readPolicy(new File("/d/o/e/s/n/t/e/x/i/s/t"));
        assertFalse(ret);
    }

    /*
     * Requested policy file is null object.
     */
    @LargeTest
    public void testINSTALL_POLICY_NULL() {
        boolean ret = ContentSecurityManager.getInstance().readPolicy(null);
        assertFalse(ret);
    }


    /*
     * Test type assignments on providers.
     * Initials:
     *    s = signature
     *    a = authority
     *    p = package
     *    e = empty (empty stanza)
     * Example: cp_sap_ap.xml will test a type stanza with
     * signature, provider and package tags versus a type stanza
     * with provider and package tags.
     */

    /*
     * sap_sap
     */
    @LargeTest
    public void testCP_SAP_SAP() {
        checkCpMMAC(R.raw.cp_sap_sap, R.raw.cp_test_apk, "test0");
    }

    /*
     * sa_sap
     */
    @LargeTest
    public void testCP_SA_SAP() {
        checkCpMMAC(R.raw.cp_sa_sap, R.raw.cp_test_apk, "test0");
    }

    /*
     * sp_sap
     */
    @LargeTest
    public void testCP_SP_SAP() {
        checkCpMMAC(R.raw.cp_sp_sap, R.raw.cp_test_apk, "test1");
    }

    /*
     * ap_sap
     */
    @LargeTest
    public void testCP_AP_SAP_TEST() {
        checkCpMMAC(R.raw.cp_ap_sap, R.raw.cp_test_apk, "test1");
    }

    /*
     * s_sap
     */
    @LargeTest
    public void testCP_S_SAP() {
        checkCpMMAC(R.raw.cp_s_sap, R.raw.cp_test_apk, "test1");
    }

    /*
     * a_sap
     */
    @LargeTest
    public void testCP_A_SAP() {
        checkCpMMAC(R.raw.cp_a_sap, R.raw.cp_test_apk, "test1");
    }

    /*
     * p_sap
     */
    @LargeTest
    public void testCP_P_SAP() {
        checkCpMMAC(R.raw.cp_p_sap, R.raw.cp_test_apk, "test1");
    }

    /*
     * sa_sa
     */
    @LargeTest
    public void testCP_SA_SA() {
        checkCpMMAC(R.raw.cp_sa_sa, R.raw.cp_test_apk, "test0");
    }

    /*
     * sp_sa
     */
    @LargeTest
    public void testCP_SP_SA() {
        checkCpMMAC(R.raw.cp_sp_sa, R.raw.cp_test_apk, "test0");
    }

    /*
     * ap_sa
     */
    @LargeTest
    public void testCP_AP_SA() {
        checkCpMMAC(R.raw.cp_ap_sa, R.raw.cp_test_apk, "test1");
    }

    /*
     * s_sa
     */
    @LargeTest
    public void testCP_S_SA() {
        checkCpMMAC(R.raw.cp_s_sa, R.raw.cp_test_apk, "test1");
    }

    /*
     * a_sa
     */
    @LargeTest
    public void testCP_A_SA() {
        checkCpMMAC(R.raw.cp_a_sa, R.raw.cp_test_apk, "test1");
    }

    /*
     * p_sa
     */
    @LargeTest
    public void testCP_P_SA() {
        checkCpMMAC(R.raw.cp_p_sa, R.raw.cp_test_apk, "test1");
    }

    /*
     * sp_sp
     */
    @LargeTest
    public void testCP_SP_SP() {
        checkCpMMAC(R.raw.cp_sp_sp, R.raw.cp_test_apk, "test0");
    }

    /*
     * ap_sp
     */
    @LargeTest
    public void testCP_AP_SP() {
        checkCpMMAC(R.raw.cp_ap_sp, R.raw.cp_test_apk, "test0");
    }

    /*
     * s_sp
     */
    @LargeTest
    public void testCP_S_SP() {
        checkCpMMAC(R.raw.cp_s_sp, R.raw.cp_test_apk, "test1");
    }

    /*
     * a_sp
     */
    @LargeTest
    public void testCP_A_SP() {
        checkCpMMAC(R.raw.cp_a_sp, R.raw.cp_test_apk, "test1");
    }

    /*
     * p_sp
     */
    @LargeTest
    public void testCP_P_SP() {
        checkCpMMAC(R.raw.cp_p_sp, R.raw.cp_test_apk, "test1");
    }

    /*
     * ap_ap
     */
    @LargeTest
    public void testCP_AP_AP() {
        checkCpMMAC(R.raw.cp_ap_ap, R.raw.cp_test_apk, "test0");
    }

    /*
     * s_ap
     */
    @LargeTest
    public void testCP_S_AP() {
        checkCpMMAC(R.raw.cp_s_ap, R.raw.cp_test_apk, "test0");
    }

    /*
     * a_ap
     */
    @LargeTest
    public void testCP_A_AP() {
        checkCpMMAC(R.raw.cp_a_ap, R.raw.cp_test_apk, "test1");
    }

    /*
     * p_ap
     */
    @LargeTest
    public void testCP_P_AP() {
        checkCpMMAC(R.raw.cp_p_ap, R.raw.cp_test_apk, "test1");
    }

    /*
     * s_s
     */
    @LargeTest
    public void testCP_S_S() {
        checkCpMMAC(R.raw.cp_s_s, R.raw.cp_test_apk, "test0");
    }

    /*
     * p_s
     */
    @LargeTest
    public void testCP_P_S() {
        checkCpMMAC(R.raw.cp_p_s, R.raw.cp_test_apk, "test1");
    }

    /*
     * a_s
     */
    @LargeTest
    public void testCP_A_S() {
        checkCpMMAC(R.raw.cp_a_s, R.raw.cp_test_apk, "test1");
    }

    /*
     * a_p
     */
    @LargeTest
    public void testCP_A_P() {
        checkCpMMAC(R.raw.cp_a_p, R.raw.cp_test_apk, "test0");
    }

    /*
     * p_e
     */
    @LargeTest
    public void testCP_P_E() {
        checkCpMMAC(R.raw.cp_p_e, R.raw.cp_test_apk, "test0");
    }

    /*
     * s_e
     */
    @LargeTest
    public void testCP_S_E() {
        checkCpMMAC(R.raw.cp_s_e, R.raw.cp_test_apk, "test0");
    }

    /*
     * a_e
     */
    @LargeTest
    public void testCP_A_E() {
        checkCpMMAC(R.raw.cp_a_e, R.raw.cp_test_apk, "test1");
    }

    /*
     * e_e
     */
    @LargeTest
    public void testCP_E_E() {
        checkCpMMAC(R.raw.cp_e_e, R.raw.cp_test_apk, "test0");
    }

    /* End of type assignment testing */


    /*
     * Given R access, try obtaining R access.
     */
    @LargeTest
    public void testCP_ALLOW_R_GIVEN_R_TEST() {
        checkProviderPolicy(R.raw.cp_allow_read, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.R, true);
    }

    /*
     * Given R access, try obtaining W access.
     */
    @LargeTest
    public void testCP_ALLOW_W_GIVEN_R_TEST() {
        checkProviderPolicy(R.raw.cp_allow_read, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.W, false);
    }

    /*
     * Given R access, try obtaining RW access.
     */
    @LargeTest
    public void testCP_ALLOW_RW_GIVEN_R_TEST() {
        checkProviderPolicy(R.raw.cp_allow_read, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.RW, false);
    }

    /*
     * Given W access, try obtaining R access.
     */
    @LargeTest
    public void testCP_ALLOW_R_GIVEN_W_TEST() {
        checkProviderPolicy(R.raw.cp_allow_write, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.R, false);
    }

    /*
     * Given W access, try obtaining W access.
     */
    @LargeTest
    public void testCP_ALLOW_W_GIVEN_W_TEST() {
        checkProviderPolicy(R.raw.cp_allow_write, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.W, true);
    }

    /*
     * Given W access, try obtaining RW access.
     */
    @LargeTest
    public void testCP_ALLOW_RW_GIVEN_W_TEST() {
        checkProviderPolicy(R.raw.cp_allow_write, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.RW, false);
    }

    /*
     * Given RW access, try obtaining R access.
     */
    @LargeTest
    public void testCP_ALLOW_R_GIVEN_RW_TEST() {
        checkProviderPolicy(R.raw.cp_allow_readwrite, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.R, true);
    }

    /*
     * Given RW access, try obtaining W access.
     */
    @LargeTest
    public void testCP_ALLOW_W_GIVEN_RW_TEST() {
        checkProviderPolicy(R.raw.cp_allow_readwrite, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.W, true);
    }

    /*
     * Given RW access, try obtaining RW access.
     */
    @LargeTest
    public void testCP_ALLOW_RW_GIVEN_RW_TEST() {
        checkProviderPolicy(R.raw.cp_allow_readwrite, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.RW, true);
    }

    /*
     * Given USE access, try obtaining R access.
     */
    @LargeTest
    public void testCP_ALLOW_R_GIVEN_USE_TEST() {
        checkProviderPolicy(R.raw.cp_use_only, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.R, false);
    }

    /*
     * Given USE access, try obtaining W access.
     */
    @LargeTest
    public void testCP_ALLOW_W_GIVEN_USE_TEST() {
        checkProviderPolicy(R.raw.cp_use_only, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.W, false);
    }

    /*
     * Given USE access, try obtaining RW access.
     */
    @LargeTest
    public void testCP_ALLOW_RW_GIVEN_USE_TEST() {
        checkProviderPolicy(R.raw.cp_use_only, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.RW, false);
    }

    /*
     * Use attributes in source-destination pair.
     */
    @LargeTest
    public void testCP_ATTR_TEST() {
        checkProviderPolicy(R.raw.cp_attribute, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.R, true);
    }

    /*
     * Single attribute that covers multiple types.
     */
    @LargeTest
    public void testCP_SAME_ATTR_TEST() {
        checkProviderPolicy(R.raw.cp_same_attr, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.R, true);
    }

    /*
     * Invalid source type (package).
     */
    @LargeTest
    public void testCP_INVALID_SRC_TEST() {
        checkProviderPolicy(R.raw.cp_deny_invalid_src, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.R, false);
    }

    /*
     * Invalid destination type (content provider).
     */
    @LargeTest
    public void testCP_INVALID_DST_TEST() {
        checkProviderPolicy(R.raw.cp_deny_invalid_dst, R.raw.cp_test_apk,
            R.raw.cp_shared_apk, ContentSecurityManager.Access.R, false);
    }

    /*
     * Test type assignments on providers.
     * Initials:
     *    s = signature
     *    a = authority
     *    p = package
     *    e = empty (empty stanza)
     *    r = read perm
     *    w = write perm
     * Example: cp_sap_ap.xml will test a type stanza with
     * signature, provider and package tags versus a type stanza
     * with provider and package tags.
     */

    /*
     * sapr_sap
     */
    @LargeTest
    public void testCP_SAPR_SAP() {
        checkCpMMAC(R.raw.cp_sapr_sap, R.raw.cp_shared_apk, "test1");
    }

    /*
     * sapw_sap
     */
    @LargeTest
    public void testCP_SAPW_SAP() {
        checkCpMMAC(R.raw.cp_sapw_sap, R.raw.cp_test_apk, "test1");
    }

    /*
     * sapr_sa
     */
    @LargeTest
    public void testCP_SAPR_SA() {
        checkCpMMAC(R.raw.cp_sapr_sa, R.raw.cp_shared_apk, "test1");
    }

    /*
     * sapw_sa
     */
    @LargeTest
    public void testCP_SAPW_SA() {
        checkCpMMAC(R.raw.cp_sapw_sa, R.raw.cp_test_apk, "test1");
    }

    /*
     * sapr_s
     */
    @LargeTest
    public void testCP_SAPR_S() {
        checkCpMMAC(R.raw.cp_sapr_s, R.raw.cp_shared_apk, "test1");
    }

    /*
     * sapw_s
     */
    @LargeTest
    public void testCP_SAPW_S() {
        checkCpMMAC(R.raw.cp_sapw_s, R.raw.cp_test_apk, "test1");
    }

    /*
     * sapr_p
     */
    @LargeTest
    public void testCP_SAPR_P() {
        checkCpMMAC(R.raw.cp_sapr_p, R.raw.cp_shared_apk, "test1");
    }

    /*
     * sapw_p
     */
    @LargeTest
    public void testCP_SAPW_P() {
        checkCpMMAC(R.raw.cp_sapw_p, R.raw.cp_test_apk, "test1");
    }

    /*
     * sapr_a
     */
    @LargeTest
    public void testCP_SAPR_A() {
        checkCpMMAC(R.raw.cp_sapr_a, R.raw.cp_shared_apk, "test1");
    }

    /*
     * sapw_a
     */
    @LargeTest
    public void testCP_SAPW_A() {
        checkCpMMAC(R.raw.cp_sapw_a, R.raw.cp_test_apk, "test1");
    }

    /*
     * sapr_ap
     */
    @LargeTest
    public void testCP_SAPR_AP() {
        checkCpMMAC(R.raw.cp_sapr_ap, R.raw.cp_shared_apk, "test1");
    }

    /*
     * sapw_ap
     */
    @LargeTest
    public void testCP_SAPW_AP() {
        checkCpMMAC(R.raw.cp_sapw_ap, R.raw.cp_test_apk, "test1");
    }

    /*
     * sapr_sp
     */
    @LargeTest
    public void testCP_SAPR_SP() {
        checkCpMMAC(R.raw.cp_sapr_sp, R.raw.cp_shared_apk, "test1");
    }

    /*
     * sapw_sp
     */
    @LargeTest
    public void testCP_SAPW_SP() {
        checkCpMMAC(R.raw.cp_sapw_sp, R.raw.cp_test_apk, "test1");
    }

    /*
     * sapr_sp
     * Policy labeling for sig|system or higher perm but found dangerous perm.
     */
    @LargeTest
    public void testCP_SAPR_SP_LOWER_PERM() {
        checkCpMMAC(R.raw.cp_sapr_sp_lower, R.raw.cp_release_apk, "test0");
    }

    /*
     * sapw_sp
     * Policy labeling for sig|system or higher perm but found dangerous perm.
     */
    @LargeTest
    public void testCP_SAPW_SP_LOWER_PERM() {
        checkCpMMAC(R.raw.cp_sapw_sp_lower, R.raw.cp_media_apk, "test0");
    }

    /*
     * sapw_sp
     * Policy labeling for sig or higher perm but found dangerous perm.
     */
    @LargeTest
    public void testCP_SAPR_SP_LOWER_PERM1() {
        checkCpMMAC(R.raw.cp_sapr_sp_lower1, R.raw.cp_release_apk, "test0");
    }

    /*
     * sapw_sp
     * Policy labeling for sig or higher perm but found dangerous perm.
     */
    @LargeTest
    public void testCP_SAPW_SP_LOWER_PERM1() {
        checkCpMMAC(R.raw.cp_sapw_sp_lower1, R.raw.cp_media_apk, "test0");
    }
}
