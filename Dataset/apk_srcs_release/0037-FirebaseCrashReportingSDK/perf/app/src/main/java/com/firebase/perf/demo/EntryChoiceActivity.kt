package com.firebase.perf.demo

import android.content.Intent
import com.firebase.example.internal.BaseEntryChoiceActivity
import com.firebase.example.internal.Choice

class EntryChoiceActivity : BaseEntryChoiceActivity() {

    override fun getChoices(): List<Choice> {
        return listOf(
            Choice(
                "Java",
                "Run the Firebase Performance Monitoring quickstart written in Java.",
                Intent(
                    this,
                    com.firebase.perf.demo.java.MainActivity::class.java,
                ),
            ),
            Choice(
                "Kotlin",
                "Run the Firebase Performance Monitoring quickstart written in Kotlin.",
                Intent(
                    this,
                    com.firebase.perf.demo.kotlin.MainActivity::class.java,
                ),
            ),
        )
    }
}
