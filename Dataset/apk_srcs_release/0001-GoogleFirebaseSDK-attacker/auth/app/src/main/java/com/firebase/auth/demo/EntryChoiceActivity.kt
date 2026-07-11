package com.google.firebase.attacker

import android.content.Intent
import com.firebase.example.internal.BaseEntryChoiceActivity
import com.firebase.example.internal.Choice

class EntryChoiceActivity : BaseEntryChoiceActivity() {

    override fun getChoices(): List<Choice> {
        return listOf(
            Choice(
                "Java",
                "Run the Firebase Auth quickstart written in Java.",
                Intent(this, com.google.firebase.attacker.java.MainActivity::class.java),
            ),
            Choice(
                "Kotlin",
                "Run the Firebase Auth quickstart written in Kotlin.",
                Intent(this, com.google.firebase.attacker.kotlin.MainActivity::class.java),
            ),
        )
    }
}
