/*
 * Copyright (C) 2006 The Android Open Source Project
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

package com.android.server.am;

import static android.view.WindowManager.LayoutParams.FLAG_SYSTEM_ERROR;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.Resources;
import android.os.Handler;
import android.os.Message;
import android.util.Slog;
import android.view.WindowManager;

class SecurityDialog extends BaseErrorDialog {
    private static final String TAG = "SecurityDialog";

    // Event 'what' codes
    static final int FORCE_CLOSE = 1;
    static final int WAIT = 2;
    static final int WAIT_AND_REPORT = 3;

    private final ActivityManagerService mService;

    public SecurityDialog(ActivityManagerService service, Context context,
            String message, boolean aboveSystem) {
        super(context);

        mService = service;
        Resources res = context.getResources();

        setCancelable(false);

        setMessage(message);

        setButton(DialogInterface.BUTTON_POSITIVE,
                res.getText(com.android.internal.R.string.force_close),
                mHandler.obtainMessage(FORCE_CLOSE));
        setButton(DialogInterface.BUTTON_NEGATIVE,
                res.getText(com.android.internal.R.string.wait),
                mHandler.obtainMessage(WAIT));

        if (aboveSystem) {
            getWindow().setType(WindowManager.LayoutParams.TYPE_SYSTEM_ERROR);
        }
        getWindow().addFlags(FLAG_SYSTEM_ERROR);
        WindowManager.LayoutParams attrs = getWindow().getAttributes();
        attrs.setTitle("Security Violation");
        attrs.privateFlags = WindowManager.LayoutParams.PRIVATE_FLAG_SHOW_FOR_ALL_USERS;
        getWindow().setAttributes(attrs);
    }

    public void onStop() {
    }

    private final Handler mHandler = new Handler() {
        public void handleMessage(Message msg) {
            Intent appErrorIntent = null;
            switch (msg.what) {
                case FORCE_CLOSE:
                    // Kill the application.
                    //mService.killAppAtUsersRequest(mProc, AppNotRespondingDialog.this);
                    break;
                case WAIT_AND_REPORT:
                case WAIT:
                    // Continue waiting for the application.
                    /*
                    synchronized (mService) {
                        ProcessRecord app = mProc;

                        if (msg.what == WAIT_AND_REPORT) {
                            appErrorIntent = mService.createAppErrorIntentLocked(app,
                                    System.currentTimeMillis(), null);
                        }

                        app.notResponding = false;
                        app.notRespondingReport = null;
                        if (app.anrDialog == AppNotRespondingDialog.this) {
                            app.anrDialog = null;
                        }
                    }
                    */
                    break;
            }
            /*
            if (appErrorIntent != null) {
                try {
                    getContext().startActivity(appErrorIntent);
                } catch (ActivityNotFoundException e) {
                    Slog.w(TAG, "bug report receiver dissappeared", e);
                }
            }
            */
        }
    };
}
