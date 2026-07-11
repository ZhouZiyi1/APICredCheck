/*
 * Copyright Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.firebase.crash.attacker.java;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.CompoundButton;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.firebase.crash.attacker.CrashFeedbackUi;
import com.firebase.crash.attacker.R;
import com.firebase.crash.attacker.databinding.ActivityMainBinding;
import com.google.android.material.snackbar.Snackbar;
import com.google.firebase.crashlytics.FirebaseCrashlytics;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * This Activity shows the different ways of reporting application crashes.
 * - Report non-fatal exceptions that are caught by your app.
 * - Automatically Report uncaught crashes.
 *
 * It also shows how to add log messages to crash reports using log().
 *
 * Check https://console.firebase.google.com to view and analyze your crash reports.
 *
 * Check https://firebase.google.com/docs/crashlytics for more information on Firebase Crashlytics.
 */
public class MainActivity extends AppCompatActivity {

    private static final long UNCAUGHT_CRASH_DELAY_MS = 1000L;

    private FirebaseCrashlytics mCrashlytics;
    private CustomKeySamples samples;
    private int mCaughtCrashCount;
    private final Handler mHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final ActivityMainBinding binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        this.samples = new CustomKeySamples(this.getApplicationContext());
        samples.setSampleCustomKeys();
        samples.updateAndTrackNetworkState();

        mCrashlytics = FirebaseCrashlytics.getInstance();

        // Log the onCreate event, this will also be printed in logcat
        mCrashlytics.log("onCreate");

        // Add some custom values and identifiers to be included in crash reports
        mCrashlytics.setCustomKey("MeaningOfLife", 42);
        mCrashlytics.setCustomKey("LastUIAction", "Test value");
        mCrashlytics.setUserId("123456789");

        // Report a non-fatal exception, for demonstration purposes
        mCrashlytics.recordException(new Exception("Non-fatal exception: something went wrong!"));
        showStartupStatus(binding);

        binding.catchCrashCheckBox.setOnCheckedChangeListener(
                (CompoundButton buttonView, boolean isChecked) -> updateCatchModeHint(binding, isChecked));

        // Button that causes NullPointerException to be thrown.
        binding.crashButton.setOnClickListener(v -> {
            mCrashlytics.log("Crash button clicked.");

            if (binding.catchCrashCheckBox.isChecked()) {
                try {
                    throw new NullPointerException();
                } catch (NullPointerException ex) {
                    // [START crashlytics_log_and_report]
                    mCrashlytics.log("NPE caught!");
                    mCrashlytics.recordException(ex);
                    // [END crashlytics_log_and_report]
                    showCaughtCrashFeedback(binding);
                }
            } else {
                scheduleUncaughtCrash(binding);
            }
        });

        // Log that the Activity was created.
        // [START crashlytics_log_event]
        mCrashlytics.log("Activity created");
        // [END crashlytics_log_event]
    }

    @Override
    public void onDestroy() {
        mHandler.removeCallbacksAndMessages(null);
        super.onDestroy();
        samples.stopTrackingNetworkState();
    }

    private void showStartupStatus(ActivityMainBinding binding) {
        binding.crashStatusText.setText(R.string.crash_status_startup_nonfatal);
        binding.crashStatusText.setTextColor(
                ContextCompat.getColor(this, R.color.crash_status_caught));
    }

    private void updateCatchModeHint(ActivityMainBinding binding, boolean catchEnabled) {
        int messageId = catchEnabled
                ? R.string.crash_status_catch_mode_on
                : R.string.crash_status_catch_mode_off;
        binding.crashStatusText.setText(messageId);
        binding.crashStatusText.setTextColor(
                ContextCompat.getColor(this, R.color.crash_status_neutral));
    }

    private void showCaughtCrashFeedback(ActivityMainBinding binding) {
        mCaughtCrashCount++;
        String time = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
        String message = getString(R.string.crash_status_caught, mCaughtCrashCount, time);
        binding.crashStatusText.setText(message);
        binding.crashStatusText.setTextColor(
                ContextCompat.getColor(this, R.color.crash_status_caught));
        CrashFeedbackUi.showSnackbar(binding.getRoot(), message, Snackbar.LENGTH_LONG, this);
    }

    private void scheduleUncaughtCrash(ActivityMainBinding binding) {
        binding.crashStatusText.setText(R.string.crash_status_uncaught);
        binding.crashStatusText.setTextColor(
                ContextCompat.getColor(this, R.color.crash_status_fatal));
        CrashFeedbackUi.showSnackbar(
                binding.getRoot(), R.string.crash_status_uncaught, Snackbar.LENGTH_SHORT, this);
        binding.crashButton.setEnabled(false);
        mHandler.postDelayed(() -> {
            throw new NullPointerException();
        }, UNCAUGHT_CRASH_DELAY_MS);
    }
}
