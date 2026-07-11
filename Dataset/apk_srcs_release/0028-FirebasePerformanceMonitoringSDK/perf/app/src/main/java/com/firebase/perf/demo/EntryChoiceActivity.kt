package com.firebase.perf.demo

import android.content.Intent
import com.firebase.example.internal.BaseEntryChoiceActivity
import com.firebase.example.internal.Choice

class EntryChoiceActivity : BaseEntryChoiceActivity() {

    override fun getChoices(): List<Choice> {
        return listOf(
            Choice(
                "Performance trace and file metrics",
                "Open starts a Firebase Performance Monitoring trace and records file read metrics.",
                Intent(
                    this,
                    com.firebase.perf.demo.kotlin.MainActivity::class.java,
                ),
            ),
        )
    }
}
