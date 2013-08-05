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

import android.content.ComponentName;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Environment;
import android.os.Process;
import android.os.SELinux;
import android.os.SystemProperties;
import android.util.Slog;
import android.util.Xml;

import com.android.internal.util.XmlUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;


/**
 * Centralized access to Intent MAC implementation. This class will parse a
 * policy file, make policy decisions, and generate messages for logging
 * purposes.
 *
 * <p>The JSON printing methods seem very complicated, but we want to
 * accomplish two goals:
 * <ol>
 *   <li>Print a machine-readable string so that tool similar in functionality
 *   to <a href="http://linux.die.net/man/1/audit2allow">audit2allow</a> can
 *   be developed for IntentMAC.</li>
 *   <li>Print a human-readable string so that the developer can understand
 *   why the Intent was blocked.</li>
 * </ol>
 * The goal for machine-readability implies using a standard exchange format
 * like XML or JSON. The goal for human-readability requires printing the JSON
 * object in a readable way. This implies printing the objects' fields in a
 * source to destination ordering. JSON does not define an ordering on
 * objects' fields, so we have to do it ourselves. Furthermore, effective
 * spacing can increase readability, but Android's implementation does not use
 * spaces, so we have to do it ourselves.
 * </p>
 *
 * TODO IntentMAC is not thread-safe. So far, this is okay in reads, but not
 * okay during reloading.
 *
 * {@hide}
 */
public final class IntentMAC {
    private static final String TAG = "IntentMMAC";
    private static final String DENIAL_PREFIX = "INTENT_DENIAL";

    public  static final boolean DEBUG_POLICY = false;
    private static final boolean DEBUG_POLICY_INSTALL = DEBUG_POLICY || false;
    public static final boolean DEBUG_ACTIVITIES = DEBUG_POLICY || false;
    public static final boolean DEBUG_BROADCASTS = DEBUG_POLICY || false;
    public static final boolean DEBUG_SERVICES = DEBUG_POLICY || false;
    public static final boolean DEBUG_PROVIDERS = DEBUG_POLICY || false;
    public static final boolean DEBUG_ICC_TRACE = false;
    public static final boolean DEBUG_ICC = DEBUG_ICC_TRACE ||
            DEBUG_ACTIVITIES || DEBUG_BROADCASTS || DEBUG_SERVICES ||
            DEBUG_PROVIDERS;

    private final File[] INTENTMAC_POLICY_FILE = {
        new File(Environment.getDataDirectory(), "security/intent_mac.xml"),
        new File(Environment.getRootDirectory(), "etc/security/intent_mac.xml"),
        null
    };

    // private instance variables
    private Set<IntentPolicy> mIntentPolicySet;
    private Set<IntentPolicy> mAllowAllPolicies;

    // inner class used to define a specific policy.
    private class IntentPolicy {
        final String name;
        final IntentFilter intentFilter;
        final String srcType;
        final String srcCtx;
        final String dstType;
        final boolean allowPolicy;

        public IntentPolicy(String name,
                IntentFilter intentFilter,
                String srcType, String srcCtx,
                String dstType,
                boolean allowPolicy) {
            this.name         = name;
            this.intentFilter = intentFilter;
            this.srcType      = srcType;
            this.srcCtx       = srcCtx;
            this.dstType      = dstType;
            this.allowPolicy  = allowPolicy;
        }
    }

    private IntentMAC() {
        readPolicy(INTENTMAC_POLICY_FILE);
    }

    private static class SingletonHolder {
        public static final IntentMAC INSTANCE = new IntentMAC();
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
                Slog.d(TAG,"Couldn't find intent policy " + policyFiles[i].getPath());
            }
            i++;
        }

        if (policyFile == null) {
            Slog.e(TAG, "Intent MMAC disabled.");
            mIntentPolicySet = null;
            mAllowAllPolicies = null;
            return false;
        }

        Slog.d(TAG, "Intent MMAC enabled using file " + policyFiles[i].getPath());
        if (DEBUG_POLICY) Slog.d(TAG, "DEBUG_POLICY=true");
        if (DEBUG_POLICY_INSTALL) Slog.d(TAG, "DEBUG_POLICY_INSTALL=true");
        if (DEBUG_ICC) Slog.d(TAG, "DEBUG_ICC=true");

        boolean enforcing = SystemProperties.getBoolean("persist.mmac.enforce", false);
        String mode = enforcing ? "enforcing" : "permissive";
        Slog.d(TAG, "Intent MMAC starting in " + mode + " mode.");

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

                if ("intent".equalsIgnoreCase(tagName)) {
                    IntentFilter filter = new IntentFilter();
                    readPolicyForIntent(parser, filter);

                } else if ("allow-all".equals(tagName)) {
                    readAllowAllPolicy(parser);

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

        Slog.d(TAG, "Loaded " + (mIntentPolicySet.size()+mAllowAllPolicies.size()) + " policy rules");
        mIntentPolicySet = Collections.unmodifiableSet(mIntentPolicySet);
        mAllowAllPolicies = Collections.unmodifiableSet(mAllowAllPolicies);
        return true;
    }

    private void readPolicyForIntent(XmlPullParser parser, IntentFilter filter)
            throws XmlPullParserException, IOException {
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
            if ("filter".equalsIgnoreCase(tagName)) {
                readFilter(parser, filter);
            } else if ("allow".equalsIgnoreCase(tagName)) {
                String ruleName = parser.getAttributeValue(null, "name");
                ruleName = (ruleName == null) ? parser.getPositionDescription() : ruleName;
                String srcCtx = parser.getAttributeValue(null, "srcctx");
                String srcType = parser.getAttributeValue(null, "src");
                String dstType = parser.getAttributeValue(null, "dst");
                IntentPolicy pol = new IntentPolicy(ruleName, filter, srcType, srcCtx, dstType, true);
                mIntentPolicySet.add(pol);
                if (DEBUG_POLICY_INSTALL) {
                    Slog.d(TAG, "Added policy " + pol.name +
                            " " + intentFilterToString(pol.intentFilter) + " " +
                            pol.srcType +
                            (pol.srcCtx != null ? ", " + pol.srcCtx : "") +
                            " => " +
                            pol.dstType);
                }
                XmlUtils.skipCurrentTag(parser);
            } else {
                XmlUtils.skipCurrentTag(parser);
            }
            //TODO "deny" -- want test to be, if intent matches at least one
            //of deny rule then block, else if intent matches none of allow
            //rules then block
        }
    }

    private void readFilter(XmlPullParser parser, IntentFilter filter)
            throws XmlPullParserException, IOException {
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
            if ("action".equalsIgnoreCase(tagName)) {
                if (filter.countActions() != 0) {
                    throw new NullPointerException("Cannot filter on multiple actions");
                }
                String value = parser.getAttributeValue(null, "name");
                if (value == null || value == "") {
                    throw new NullPointerException("Empty name attribute");
                }
                filter.addAction(value);
            } else if ("category".equalsIgnoreCase(tagName)) {
                String value = parser.getAttributeValue(null, "name");
                if (value == null || value == "") {
                    throw new NullPointerException("Empty name attribute");
                }
                filter.addCategory(value);
            } else if ("data".equalsIgnoreCase(tagName)) {
                int attributeCount = parser.getAttributeCount();
                if (attributeCount > 1) {
                    throw new XmlPullParserException("Too many data attributes");
                }

                String name = parser.getAttributeName(0);
                if ("scheme".equalsIgnoreCase(name)) {
                    String value = parser.getAttributeValue(null, "scheme");
                    if (value == null || value == "") {
                        throw new NullPointerException("Empty data:scheme attribute");
                    }
                    filter.addDataScheme(value);
                } else if ("mimeType".equalsIgnoreCase(name)) {
                    String value = parser.getAttributeValue(null, "mimeType");
                    if (value == null || value == "") {
                        throw new NullPointerException("Empty data:mimeType attribute");
                    }
                    try {
                        filter.addDataType(value);
                    } catch (IntentFilter.MalformedMimeTypeException e) {
                        Slog.w(TAG, "Malformed mimeType");
                    }
                }
            }

            XmlUtils.skipCurrentTag(parser);
        }

        if (DEBUG_POLICY_INSTALL) {
            Slog.d(TAG, "Found intent filter " +
                    intentFilterToString(filter));
        }
    }

    private void readAllowAllPolicy(XmlPullParser parser)
            throws XmlPullParserException, IOException {
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
            if ("allow".equalsIgnoreCase(tagName)) {
                String ruleName = parser.getAttributeValue(null, "name");
                ruleName = (ruleName == null) ? parser.getPositionDescription() : ruleName;
                String srcType = parser.getAttributeValue(null, "src");
                String srcCtx = parser.getAttributeValue(null, "srcctx");
                String dstType = parser.getAttributeValue(null, "dst");
                IntentPolicy pol = new IntentPolicy(ruleName, null, srcType, srcCtx, dstType, true);
                mAllowAllPolicies.add(pol);
                if (DEBUG_POLICY_INSTALL) {
                    Slog.d(TAG, "Added allow-all policy " + pol.name
                            + " " + srcType + " => " + dstType);
                }
            }

            XmlUtils.skipCurrentTag(parser);
        }
    }

    private void flushPolicy() {
        mIntentPolicySet = new HashSet<IntentPolicy>();
        mAllowAllPolicies = new HashSet<IntentPolicy>();
    }


    /**
     * If policy is not loaded, all the check functions return true.
     */
    public static boolean isPolicyLoaded() {
        return getInstance().mIntentPolicySet != null
                && getInstance().mAllowAllPolicies != null;
    }

    /**
     * Returns a shared instance of IntentMAC which can be used to query
     * security policy for intent filtering decisions.
     * @param  none
     * @return shared instance of IntentMAC.
     */
    public static IntentMAC getInstance() {
        return SingletonHolder.INSTANCE;
    }

    /**
     * Forces a reloading of the IntentMAC policy file.
     * @param  none
     * @return none
     */
    public void reloadPolicy() {
        readPolicy(INTENTMAC_POLICY_FILE);
    }

    /**
     * Checks the relationship between the list of source and destination types
     * within the IntentMAC policy and returns true or false if this is an
     * allowed operation or not.
     * TODO Access-Vector-Cache?
     * @param  intent    the intent which will be filtered
     * @param  srcTypes  the source types
     * @param  dstTypes  the destination types
     * @return true or false based off the IntentMAC policy
     */
    public static boolean checkIntentPolicy(Intent intent,
            Iterable<String> srcTypes, Iterable<String> dstTypes) {
        if (!isPolicyLoaded()) return true;
        if (getInstance().mIntentPolicySet.size() <= 0
                && getInstance().mAllowAllPolicies.size() <= 0) {
            return false;
        }

        if (getInstance().checkIntentPolicy(intent, (String)null, (String)null)) {
            return true;
        }

        for (String srcType : srcTypes) {
            for (String dstType : dstTypes) {
                if (getInstance().checkIntentPolicy(intent, srcType, dstType)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Checks the source and destination package relationship for the intent
     * within the IntentMAC policy and returns true or false if this is an
     * allowed operation or not.
     * TODO Access-Vector-Cache?
     * @param  intent  the intent which will be filtered
     * @param  srcType  the source package name
     * @param  dstType  the destination package name
     * @return true or false based off the IntentMAC policy
     */
    private boolean checkIntentPolicy(Intent intent, String srcType, String dstType) {
        String srcCtx = SELinux.getPidContext(intent.mCreatorPid);

        for (IntentPolicy policy : mAllowAllPolicies) {
            if (DEBUG_ICC_TRACE) {
                Slog.d(TAG, "Testing against allow-all policy " + policy.name + ":"+
                        " srcType="+policy.srcType +
                        " srcCtx="+policy.srcCtx +
                        " dstType="+policy.dstType);
            }
            if ((policy.srcType == null || policy.srcType.equals(srcType)) &&
                    (policy.dstType == null || policy.dstType.equals(dstType)) &&
                    (policy.srcCtx == null || policy.srcCtx.equals(srcCtx))) {
                if (DEBUG_ICC) {
                    Slog.d(TAG, "MMAC_ALLOW name=" + policy.name);
                }
                return policy.allowPolicy;
            }
        }

        // iterate over policy set looking for a match
        for (IntentPolicy policy : mIntentPolicySet) {
            if (intentFilterMatch(policy.intentFilter, intent)) {
                if (DEBUG_ICC_TRACE) {
                    Slog.d(TAG, "Testing against policy " + policy.name +
                            " srcType="+policy.srcType +
                            " srcCtx="+policy.srcCtx +
                            " dstType="+policy.dstType);
                }
                if ((policy.srcType == null || policy.srcType.equals(srcType)) &&
                        (policy.dstType == null || policy.dstType.equals(dstType)) &&
                        (policy.srcCtx == null || policy.srcCtx.equals(srcCtx))) {
                    if (DEBUG_ICC) {
                        Slog.d(TAG, "MMAC_ALLOW name=" + policy.name);
                    }
                    return policy.allowPolicy;
                }
            }
        }
        return false;
    }

    /**
     * True turns on MAC enforcing mode.
     */
    public static String BOOLEAN_ENFORCING_NAME = "persist.mmac.enforce";
    public static boolean BOOLEAN_ENFORCING_DEFAULT = false;

    /**
     * True allows intents going to an app's own component. This reduces amount of work required
     * to create useful policy. If an app gets owned, this allows malicious code to send an
     * Intent to an component running in the same process.
     */
    public static String BOOLEAN_ALLOWSELF_NAME = "persist.mac_intent_allowSelf";
    public static boolean BOOLEAN_ALLOWSELF_DEFAULT = true;

    /**
     * True allows all intents coming from the system_server. This reduces the amount of work
     * required to create useful policy.
     */
    public static String BOOLEAN_ALLOWSYSTEM_NAME = "persist.mac_intent_allowSystem";
    public static boolean BOOLEAN_ALLOWSYSTEM_DEFAULT = true;

    /**
     * True allows apps signed with the same signature to bypass checks. This boolean is intended
     * to allow custom intents to work between apps that were written by the same author.
     */
    public static String BOOLEAN_ALLOWSIG_NAME = "persist.mac_intent_allowSig";
    public static boolean BOOLEAN_ALLOWSIG_DEFAULT = true;

    /**
     * True allows apps running with the same UID to bypass checks. This boolean is a little
     * stronger than same signature, since apps can have different UIDs but authored by the same
     * developer.
     */
    public static String BOOLEAN_ALLOWUID_NAME = "persist.mac_intent_allowUid";
    public static boolean BOOLEAN_ALLOWUID_DEFAULT = true;

    /**
     * True prints a JSON formatted debugging string
     */
    public static String BOOLEAN_PRINTJSON_NAME = "persist.mac_intent_printJSON";
    public static boolean BOOLEAN_PRINTJSON_DEFAULT = false;

    public static boolean checkAllowAllBooleans(Intent intent) {
        if (!isPolicyLoaded()) return true;

        if (SystemProperties.getBoolean(BOOLEAN_ALLOWSYSTEM_NAME,
                BOOLEAN_ALLOWSYSTEM_DEFAULT)) {
            if (Process.myPid() == intent.mCreatorPid) {
                if (DEBUG_ICC) {
                    Slog.v(TAG, "MMAC_ALLOW_ALL rule=bool_system" +
                            " creatorPid=" + intent.mCreatorPid +
                            " intent=" + intent);
                }
                return true;
            }
        }

        return false;
    }

    public static boolean checkAllowPkgBooleans(Intent intent,
            PackageParser.Package sourcePackage,
            PackageParser.Package destinationPackage) {
        if (!isPolicyLoaded()) return true;

        if (SystemProperties.getBoolean(BOOLEAN_ALLOWSELF_NAME,
                BOOLEAN_ALLOWSELF_DEFAULT)) {
            String srcName = sourcePackage.packageName;
            String dstName = destinationPackage.packageName;
            if (srcName.equals(dstName)) {
                if (DEBUG_ICC) {
                    Slog.v(TAG, "MMAC_ALLOW_PKG rule=bool_self" +
                            " intent=" + intent +
                            " srcPkg=" + srcName +
                            " dstPkg=" + dstName);
                }
                return true;
            }
        }

        if (SystemProperties.getBoolean(BOOLEAN_ALLOWSIG_NAME,
                BOOLEAN_ALLOWSIG_DEFAULT)) {
            for (Signature srcSig : sourcePackage.mSignatures) {
                for (Signature dstSig : destinationPackage.mSignatures) {
                    if (srcSig.equals(dstSig)) {
                        if (DEBUG_ICC) {
                            Slog.v(TAG, "MMAC_ALLOW_PKG rule=bool_sig" +
                                    " intent=" + intent +
                                    " srcPkg=" + sourcePackage.packageName +
                                    "("+sourcePackage.mSignatures.length+")" +
                                    " dstPkg=" + destinationPackage.packageName +
                                    "("+destinationPackage.mSignatures.length+")" +
                                    " sig=" + srcSig.toCharsString());
                        }
                        return true;
                    }
                }
            }
        }

        return false;
    }

    public static boolean isEnforcing() {
        return SystemProperties.getBoolean(BOOLEAN_ENFORCING_NAME,
                BOOLEAN_ENFORCING_DEFAULT);
    }

    public static String generateDenialString(Intent intent,
            int callingPid, Collection<PackageParser.Package> callingPkgs, Collection<String> callingTypes,
            PackageParser.Package dstPkg, Collection<String> dstTypes) {
        Set<String> callingPkgNames = new HashSet<String>(callingPkgs.size());
        for (PackageParser.Package pkg : callingPkgs) {
            callingPkgNames.add(pkg.packageName);
        }
        Set<String> dstPkgNames = new HashSet<String>(1);
        dstPkgNames.add(dstPkg.packageName);
        return generateDenialString(intent, callingPid, callingPkgNames, callingTypes, dstPkgNames, dstTypes);
    }

    public static String generateDenialString(Intent intent,
            int callingPid, Collection<String> callingPkgNames, Collection<String> callingTypes,
            Collection<String> dstPkgNames, Collection<String> dstTypes) {
        try {
            JSONObject i = new JSONObject();
            Set<String> categories = intent.getCategories();
            ComponentName component = intent.getComponent();
            i.put("action", intent.getAction());
            if (component != null) i.put("component", component.flattenToString());
            if (categories != null) i.put("categories", new JSONArray(categories));
            i.put("data", intent.getDataString());

            JSONObject j = new JSONObject();
            j.put("intent", i);
            j.put("callingPid", callingPid);
            j.put("callingPkgs", new JSONArray(callingPkgNames));
            j.put("callingTypes", new JSONArray(callingTypes));
            j.put("destPkgs", new JSONArray(dstPkgNames));
            j.put("destTypes", new JSONArray(dstTypes));

            String[] myOrdering = {"intent", "callingPid", "callingPkgs", "callingTypes", "destPkgs", "destTypes" };
            Comparator<String> myComparator = createSpecifiedOrderComparator(myOrdering);
            Map<String, Comparator<String>> comparators = new HashMap<String, Comparator<String>>(1);
            String[] intentOrder = { "component", "action", "categories", "data"};
            comparators.put("intent", createSpecifiedOrderComparator(intentOrder));

            return DENIAL_PREFIX + ": " + JSONtoSortedString(j, myComparator, comparators);
        } catch (JSONException e) {
            Slog.e(TAG, "Error when creating JSON denial string", e);
            return DENIAL_PREFIX;
        }
    }

    /**
     * Returns a valid JSON string for the JSON object, but with the names
     * in a sorted order.
     *
     * @param j the JSON object to stringify
     * @param thisComparator defines an ordering of the names
     * @param comparators a map where the keys are names of objects and the
     * the values define an ordering of the names for that object
     * @throws JSONException
     */
    private static String JSONtoSortedString(JSONObject j,
            Comparator<String> thisComparator,
            Map<String, Comparator<String>> comparators) throws JSONException {
        SortedSet<String> names = new TreeSet<String>(thisComparator);
        Iterator<String> iter = j.keys();
        while (iter.hasNext()) {
            names.add(iter.next());
        }
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        for (String name : names) {
            if (sb.length() > 1) sb.append(", ");
            sb.append('"').append(name).append('"');
            sb.append(":");
            String value = null;
            if (value == null) {
                Object o = j.get(name);
                if (o instanceof Boolean || o instanceof Double
                        || o instanceof Integer || o instanceof Long) {
                    sb.append(o);
                } else if (o instanceof String) {
                    sb.append(JSONObject.quote((String)o));
                } else if (JSONObject.NULL.equals(o)) {
                    sb.append("null");
                } else if (o instanceof JSONObject) {
                    Comparator<String> cmp = comparators.get(name);
                    cmp = cmp == null ? String.CASE_INSENSITIVE_ORDER : cmp;
                    sb.append(JSONtoSortedString((JSONObject)o, cmp, comparators));
                } else if (o instanceof JSONArray) {
                    JSONArray arr = (JSONArray)o;
                    sb.append(arr.toString());
                } else {
                    throw new JSONException("Unhandled type " + o.getClass().getSimpleName()
                            + " for field " + name + ".");
                }
            }
            if (value == null) {

            }
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Creates a {@link Comparator} that uses an the ordering of elements in
     * an {@link Array} as the ordering for the Comparator.
     *
     * <p>The elements of the Array should be a type that implements
     * {@link Object#equals(Object)} in some sane way.</p>
     */
    private static <T> Comparator<T> createSpecifiedOrderComparator(final T[] ordering) {
        Comparator<T> myComparator = new Comparator<T>() {
            Map<T, Integer> lookupMap = new HashMap<T, Integer>(ordering.length);
            int lookup(T s) {
                if (lookupMap.containsKey(s)) return lookupMap.get(s);

                for (int i = 0; i < ordering.length; ++i) {
                    if (s.equals(ordering[i])) {
                        lookupMap.put(s, i);
                        return i;
                    }
                }
                throw new IllegalArgumentException("String " + s + " not a valid name.");
            }
            @Override
            public int compare(T lhs, T rhs) {
                int lhi = lookup(lhs);
                int rhi = lookup(rhs);
                return lhi-rhi;
            }
        };
        return myComparator;
    }

    private static String intentFilterToString(IntentFilter filter) {
        StringBuilder sb = new StringBuilder();
        sb.append("(");

        sb.append("[");
        for (int i = 0, j = filter.countActions(); i < j; ++i) {
            sb.append(filter.getAction(i));
            if (i != j-1) sb.append(",");
        }
        sb.append("]");
        sb.append(",");

        sb.append("[");
        for (int i = 0, j = filter.countCategories(); i < j; ++i) {
            sb.append(filter.getCategory(i));
            if (i != j-1) sb.append(",");
        }
        sb.append("]");

        sb.append(")");
        return sb.toString();
    }

    private static boolean intentFilterMatch(IntentFilter filter, Intent intent) {
        int val = filter.match(null, intent, false, TAG);
        return (val != IntentFilter.NO_MATCH_TYPE &&
                val != IntentFilter.NO_MATCH_DATA &&
                val != IntentFilter.NO_MATCH_ACTION &&
                val != IntentFilter.NO_MATCH_CATEGORY);
    }
}
