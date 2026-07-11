package com.firebase.auth.attacker.kotlin

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.navigation.findNavController
import com.firebase.auth.attacker.R
import com.firebase.auth.attacker.TestSignals

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        Log.i(TestSignals.TAG, TestSignals.READY)
        findNavController(R.id.nav_host_fragment).setGraph(R.navigation.nav_graph_kotlin)
    }
}
