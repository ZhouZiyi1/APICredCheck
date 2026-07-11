package com.firebase.crash.demo.kotlin

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.CompoundButton
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.firebase.crash.demo.CrashFeedbackUi
import com.firebase.crash.demo.R
import com.google.android.material.snackbar.Snackbar
import com.google.firebase.crashlytics.FirebaseCrashlytics
import com.google.firebase.crashlytics.crashlytics
import com.google.firebase.crashlytics.setCustomKeys
import com.google.firebase.Firebase
import com.firebase.crash.demo.databinding.ActivityMainBinding
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

        crashlytics = Firebase.crashlytics

        // Log the onCreate event, this will also be printed in logcat
        crashlytics.log("onCreate")

        // Add some custom values and identifiers to be included in crash reports
        crashlytics.setCustomKeys {
            key("MeaningOfLife", 42)
            key("LastUIAction", "Test value")
        }
        crashlytics.setUserId("123456789")

        // Report a non-fatal exception, for demonstration purposes
        crashlytics.recordException(Exception("Non-fatal exception: something went wrong!"))
        showStartupStatus(binding)

        binding.catchCrashCheckBox.setOnCheckedChangeListener { _, isChecked ->
            updateCatchModeHint(binding, isChecked)
        }

        binding.crashButton.setOnClickListener {
            crashlytics.log("Crash button clicked.")

            if (binding.catchCrashCheckBox.isChecked) {
                try {
                    throw NullPointerException()
                } catch (ex: NullPointerException) {
                    // [START crashlytics_log_and_report]
                    crashlytics.log("NPE caught!")
                    crashlytics.recordException(ex)
                    // [END crashlytics_log_and_report]
                    showCaughtCrashFeedback(binding)
                }
            } else {
                scheduleUncaughtCrash(binding)
            }
        }

        // Log that the Activity was created.
        // [START crashlytics_log_event]
        crashlytics.log("Activity created")
        // [END crashlytics_log_event]
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
        customKeySamples.stopTrackingNetworkState()
    }

    private fun showStartupStatus(binding: ActivityMainBinding) {
        binding.crashStatusText.setText(R.string.crash_status_startup_nonfatal)
        binding.crashStatusText.setTextColor(
            ContextCompat.getColor(this, R.color.crash_status_caught),
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

    companion object {
        private const val UNCAUGHT_CRASH_DELAY_MS = 1000L
    }
}
