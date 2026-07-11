package com.firebase.crash.demo

import android.content.Intent
import com.firebase.example.internal.BaseEntryChoiceActivity
import com.firebase.example.internal.Choice

class EntryChoiceActivity : BaseEntryChoiceActivity() {

    override fun getChoices(): List<Choice> {
        return listOf(
            Choice(
                "Crashlytics non-fatal report",
                "Open records a non-fatal exception through Firebase Crashlytics and shows the result.",
                Intent(this, com.firebase.crash.demo.kotlin.MainActivity::class.java),
            ),
        )
    }
}
