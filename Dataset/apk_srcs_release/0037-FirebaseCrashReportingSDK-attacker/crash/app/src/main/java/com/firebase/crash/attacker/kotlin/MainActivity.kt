package com.firebase.crash.attacker.kotlin

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.firebase.crash.attacker.CrashFeedbackUi
import com.firebase.crash.attacker.R
import com.firebase.crash.attacker.TestSignals
import com.google.android.material.snackbar.Snackbar
import com.google.firebase.FirebaseApp
import com.google.firebase.crashlytics.FirebaseCrashlytics
import com.google.firebase.crashlytics.crashlytics
import com.google.firebase.crashlytics.setCustomKeys
import com.google.firebase.Firebase
import com.firebase.crash.attacker.databinding.ActivityMainBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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
class MainActivity : AppCompatActivity() {

    private lateinit var crashlytics: FirebaseCrashlytics
    private lateinit var customKeySamples: CustomKeySamples
    private var caughtCrashCount = 0
    private val handler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        customKeySamples = CustomKeySamples(applicationContext)
        customKeySamples.setSampleCustomKeys()
        customKeySamples.updateAndTrackNetworkState()

        showStartupStatus(binding)

        binding.catchCrashCheckBox.setOnCheckedChangeListener { _, isChecked ->
            updateCatchModeHint(binding, isChecked)
        }

        binding.crashButton.setOnClickListener {
            if (!validateConfiguredApiKey(binding)) {
                return@setOnClickListener
            }

            initializeCrashlytics()
            crashlytics.log("Crash button clicked.")

            if (binding.catchCrashCheckBox.isChecked) {
                try {
                    throw NullPointerException()
                } catch (ex: NullPointerException) {
                    // [START crashlytics_log_and_report]
                    Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_START}: Crashlytics.recordException caught crash")
                    crashlytics.log("NPE caught!")
                    crashlytics.recordException(ex)
                    // [END crashlytics_log_and_report]
                    showCaughtCrashFeedback(binding)
                    Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_SUCCESS}: caught crash recorded")
                    Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE)
                }
            } else {
                Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_START}: Crashlytics uncaught crash")
                scheduleUncaughtCrash(binding)
            }
        }

        // Log that the Activity was created.
        // [START crashlytics_log_event]
        binding.crashButton.postDelayed({
            Log.i(TestSignals.TAG, TestSignals.MAIN_AUTO_CLICK_CRASH)
            binding.crashButton.performClick()
        }, TestSignals.MAIN_AUTO_CLICK_DELAY_MS)
        // [END crashlytics_log_event]
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
        customKeySamples.stopTrackingNetworkState()
    }

    private fun showStartupStatus(binding: ActivityMainBinding) {
        binding.crashStatusText.setText(R.string.crash_status_idle)
        binding.crashStatusText.setTextColor(
            ContextCompat.getColor(this, R.color.crash_status_neutral),
        )
    }

    private fun updateCatchModeHint(binding: ActivityMainBinding, catchEnabled: Boolean) {
        val messageId = if (catchEnabled) {
            R.string.crash_status_catch_mode_on
        } else {
            R.string.crash_status_catch_mode_off
        }
        binding.crashStatusText.setText(messageId)
        binding.crashStatusText.setTextColor(
            ContextCompat.getColor(this, R.color.crash_status_neutral),
        )
    }

    private fun showCaughtCrashFeedback(binding: ActivityMainBinding) {
        caughtCrashCount++
        val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        val message = getString(R.string.crash_status_caught, caughtCrashCount, time)
        binding.crashStatusText.text = message
        binding.crashStatusText.setTextColor(
            ContextCompat.getColor(this, R.color.crash_status_caught),
        )
        CrashFeedbackUi.showSnackbar(binding.root, message, Snackbar.LENGTH_LONG, this)
    }

    private fun scheduleUncaughtCrash(binding: ActivityMainBinding) {
        binding.crashStatusText.setText(R.string.crash_status_uncaught)
        binding.crashStatusText.setTextColor(
            ContextCompat.getColor(this, R.color.crash_status_fatal),
        )
        CrashFeedbackUi.showSnackbar(
            binding.root,
            R.string.crash_status_uncaught,
            Snackbar.LENGTH_SHORT,
            this,
        )
        binding.crashButton.isEnabled = false
        handler.postDelayed({ throw NullPointerException() }, UNCAUGHT_CRASH_DELAY_MS)
    }

    private fun initializeCrashlytics() {
        if (::crashlytics.isInitialized) {
            return
        }

        crashlytics = Firebase.crashlytics
        crashlytics.log("onCreate")
        crashlytics.setCustomKeys {
            key("MeaningOfLife", 42)
            key("LastUIAction", "Test value")
        }
        crashlytics.setUserId("123456789")
        crashlytics.log("Activity created")
    }

    private fun validateConfiguredApiKey(binding: ActivityMainBinding): Boolean {
        Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_START}: Firebase Crashlytics API key check")
        val configuredApiKey = try {
            FirebaseApp.getInstance().options.apiKey.orEmpty()
        } catch (exception: IllegalStateException) {
            failApiKeyCheck(binding, "FirebaseApp was not initialized", exception)
            return false
        }

        if (configuredApiKey != EXPECTED_API_KEY) {
            failApiKeyCheck(binding, getString(R.string.api_call_failed_invalid_key), null)
            return false
        }

        Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_SUCCESS}: Firebase Crashlytics API key accepted")
        return true
    }

    private fun failApiKeyCheck(
        binding: ActivityMainBinding,
        message: String,
        throwable: Throwable?,
    ) {
        val statusText = "API returned: failure; $message"
        binding.crashStatusText.text = statusText
        binding.crashStatusText.setTextColor(
            ContextCompat.getColor(this, R.color.crash_status_fatal),
        )
        binding.crashButton.isEnabled = true
        if (throwable == null) {
            Log.e(TestSignals.TAG, "${TestSignals.SDK_CALL_FAILURE}: $message")
        } else {
            Log.e(TestSignals.TAG, "${TestSignals.SDK_CALL_FAILURE}: $message", throwable)
        }
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE)
        CrashFeedbackUi.showSnackbar(
            binding.root,
            getString(R.string.api_call_failure),
            Snackbar.LENGTH_LONG,
            this,
        )
    }

    companion object {
        private const val UNCAUGHT_CRASH_DELAY_MS = 1000L
        private const val EXPECTED_API_KEY = "AIzaSy11111111111111111111111_111111111"
    }
}
