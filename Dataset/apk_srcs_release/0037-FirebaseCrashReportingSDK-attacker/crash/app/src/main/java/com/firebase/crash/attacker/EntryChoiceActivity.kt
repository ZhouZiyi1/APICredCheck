package com.firebase.crash.attacker

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Button
import androidx.recyclerview.widget.RecyclerView
import com.firebase.example.internal.BaseEntryChoiceActivity
import com.firebase.example.internal.Choice

class EntryChoiceActivity : BaseEntryChoiceActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i(TestSignals.TAG, TestSignals.READY)
        findViewById<RecyclerView>(com.firebase.example.internal.R.id.choices_recycler).postDelayed({
            val openButton = findViewById<RecyclerView>(com.firebase.example.internal.R.id.choices_recycler)
                .findViewHolderForAdapterPosition(0)
                ?.itemView
                ?.findViewById<Button>(com.firebase.example.internal.R.id.item_launch_button)
            if (openButton == null) {
                Log.e(TestSignals.TAG, "${TestSignals.SDK_CALL_FAILURE}: Open button was not available")
                Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE)
                startActivity(crashIntent())
            } else {
                Log.i(TestSignals.TAG, TestSignals.MAIN_AUTO_CLICK_OPEN)
                openButton.performClick()
            }
        }, TestSignals.MAIN_AUTO_CLICK_DELAY_MS)
    }

    override fun getChoices(): List<Choice> {
        return listOf(
            Choice(
                "Crashlytics non-fatal report",
                "Open records a non-fatal exception through Firebase Crashlytics and shows the result.",
                crashIntent(),
            ),
        )
    }

    private fun crashIntent(): Intent {
        return Intent(this, com.firebase.crash.attacker.kotlin.MainActivity::class.java)
    }
}
