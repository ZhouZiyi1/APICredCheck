package com.google.tagmanager.demo

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.tagmanager.demo.databinding.ActivityMainBinding
import com.google.firebase.analytics.FirebaseAnalytics
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var firebaseAnalytics: FirebaseAnalytics
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        firebaseAnalytics = FirebaseAnalytics.getInstance(this)

        binding.btnLogCustomEvent.setOnClickListener { logShareImageEvent() }
        binding.btnSetUserProperty.setOnClickListener { setFavoriteFoodProperty() }
        binding.btnLogScreenView.setOnClickListener { logScreenView() }
        binding.btnLogPurchase.setOnClickListener { logPurchaseEvent() }
        binding.btnSetUserId.setOnClickListener { setDemoUserId() }
        binding.btnOpenGtmContainer.setOnClickListener { showGtmContainerInfo() }
        binding.btnClearLog.setOnClickListener { binding.tvLog.text = "" }

        appendLog(getString(R.string.log_startup_1))
        appendLog(getString(R.string.log_startup_2))
    }

    private fun logShareImageEvent() {
        val params = Bundle().apply {
            putString("image_name", "demo_banner.png")
            putString("full_text", "Hello from GTM Demo at ${timeFormat.format(Date())}")
        }
        appendLog(getString(R.string.api_call_start, "logEvent share_image"))
        firebaseAnalytics.logEvent("share_image", params)
        appendLog(getString(R.string.log_share_image))
        appendLog(getString(R.string.api_call_success, "share_image"))
        toast(getString(R.string.toast_share_image))
    }

    private fun setFavoriteFoodProperty() {
        val food = listOf("pizza", "sushi", "noodles").random()
        appendLog(getString(R.string.api_call_start, "setUserProperty favorite_food"))
        firebaseAnalytics.setUserProperty("favorite_food", food)
        appendLog(getString(R.string.log_user_property, food))
        appendLog(getString(R.string.api_call_success, "favorite_food"))
        toast(getString(R.string.toast_user_property, food))
    }

    private fun logScreenView() {
        val params = Bundle().apply {
            putString(FirebaseAnalytics.Param.SCREEN_NAME, "demo_main")
            putString(FirebaseAnalytics.Param.SCREEN_CLASS, "MainActivity")
        }
        appendLog(getString(R.string.api_call_start, "logEvent SCREEN_VIEW"))
        firebaseAnalytics.logEvent(FirebaseAnalytics.Event.SCREEN_VIEW, params)
        appendLog(getString(R.string.log_screen_view))
        appendLog(getString(R.string.api_call_success, "SCREEN_VIEW"))
        toast(getString(R.string.toast_screen_view))
    }

    private fun logPurchaseEvent() {
        val params = Bundle().apply {
            putString(FirebaseAnalytics.Param.TRANSACTION_ID, "T-${System.currentTimeMillis()}")
            putDouble(FirebaseAnalytics.Param.VALUE, 9.99)
            putString(FirebaseAnalytics.Param.CURRENCY, "USD")
            putString(FirebaseAnalytics.Param.ITEM_ID, "sku_demo_001")
            putString(FirebaseAnalytics.Param.ITEM_NAME, "Demo Item")
        }
        appendLog(getString(R.string.api_call_start, "logEvent PURCHASE"))
        firebaseAnalytics.logEvent(FirebaseAnalytics.Event.PURCHASE, params)
        appendLog(getString(R.string.log_purchase))
        appendLog(getString(R.string.api_call_success, "PURCHASE"))
        toast(getString(R.string.toast_purchase))
    }

    private fun setDemoUserId() {
        val userId = "demo_user_${System.currentTimeMillis() % 10000}"
        appendLog(getString(R.string.api_call_start, "setUserId"))
        firebaseAnalytics.setUserId(userId)
        appendLog(getString(R.string.log_set_user_id, userId))
        appendLog(getString(R.string.api_call_success, "user_id"))
        toast(getString(R.string.toast_user_id, userId))
    }

    private fun showGtmContainerInfo() {
        val containerId = getString(R.string.gtm_container_id)
        if (containerId.startsWith("GTM-") && !containerId.contains("XXXX")) {
            appendLog(getString(R.string.log_gtm_container_id, containerId))
            appendLog(getString(R.string.log_gtm_default_path, containerId))
            appendLog(getString(R.string.log_gtm_auto_load))
            appendLog(getString(R.string.log_gtm_preview))
            toast(getString(R.string.toast_gtm_managed))
        } else {
            appendLog(getString(R.string.log_gtm_id_missing))
            toast(getString(R.string.toast_gtm_id_missing))
        }
    }

    private fun appendLog(message: String) {
        val line = "[${timeFormat.format(Date())}] $message\n"
        binding.tvLog.append(line)
        binding.scrollLog.post { binding.scrollLog.fullScroll(android.view.View.FOCUS_DOWN) }
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }
}
