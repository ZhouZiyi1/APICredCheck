package com.firebase.perf.attacker.kotlin

import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.bumptech.glide.Glide
import com.bumptech.glide.load.DataSource
import com.bumptech.glide.load.engine.GlideException
import com.bumptech.glide.request.RequestListener
import com.bumptech.glide.request.target.Target
import com.firebase.perf.attacker.TestSignals
import com.google.android.gms.tasks.OnCompleteListener
import com.google.android.gms.tasks.Task
import com.google.android.gms.tasks.TaskCompletionSource
import com.google.firebase.Firebase
import com.google.firebase.FirebaseApp
import com.google.firebase.perf.performance
import com.google.firebase.perf.metrics.Trace
import com.firebase.perf.attacker.R
import com.firebase.perf.attacker.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.util.Random
import java.util.concurrent.CountDownLatch

class MainActivity : AppCompatActivity() {

    private lateinit var trace: Trace

    private val numStartupTasks = CountDownLatch(2)

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        if (!validateConfiguredApiKey()) {
            return
        }

        binding.button.setOnClickListener {
            Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_START}: writeStringToFile")
            // write 40 chars of random text to file
            val contentFile = File(this.filesDir, CONTENT_FILE)

            writeStringToFile(contentFile.absolutePath, "${getRandomString(40)}\n")
                .addOnCompleteListener { task ->
                    if (!task.isSuccessful) {
                        Log.e(TAG, "Unable to write to file", task.exception)
                        Log.e(
                            TestSignals.TAG,
                            "${TestSignals.SDK_CALL_FAILURE}: writeStringToFile failed",
                            task.exception,
                        )
                        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE)
                        return@addOnCompleteListener
                    }

                    Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_SUCCESS}: writeStringToFile completed")
                    loadFileFromDisk()
                }
        }

        // Begin tracing app startup tasks.
        Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_START}: Firebase.performance.newTrace($STARTUP_TRACE_NAME)")
        trace = Firebase.performance.newTrace(STARTUP_TRACE_NAME)
        Log.d(TAG, "Starting trace")
        trace.start()
        loadImageFromWeb()
        // Increment the counter of number of requests sent in the trace.
        Log.d(TAG, "Incrementing number of requests counter in trace")
        trace.incrementMetric(REQUESTS_COUNTER_NAME, 1)
        loadFileFromDisk()
        // Wait for app startup tasks to complete asynchronously and stop the trace.
        Thread(
            Runnable {
                try {
                    numStartupTasks.await()
                } catch (e: InterruptedException) {
                    Log.e(TAG, "Unable to wait for startup task completion.")
                } finally {
                    Log.d(TAG, "Stopping trace")
                    trace.stop()
                    Log.i(
                        TestSignals.TAG,
                        "${TestSignals.SDK_CALL_SUCCESS}: trace=$STARTUP_TRACE_NAME stopped; metric=$REQUESTS_COUNTER_NAME",
                    )
                    Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE)
                    runOnUiThread {
                        binding.textViewContent.text =
                            "API returned: Firebase Performance trace '$STARTUP_TRACE_NAME' completed."
                        Toast.makeText(
                            this,
                            "Trace completed",
                            Toast.LENGTH_SHORT,
                        ).show()
                    }
                }
            },
        ).start()
    }

    private fun loadImageFromWeb() {
        Glide.with(this).load(IMAGE_URL)
            .placeholder(ColorDrawable(ContextCompat.getColor(this, R.color.colorAccent)))
            .listener(object : RequestListener<Drawable> {
                override fun onLoadFailed(
                    e: GlideException?,
                    model: Any?,
                    target: Target<Drawable>?,
                    isFirstResource: Boolean,
                ): Boolean {
                    Log.w(TAG, "Image load failed during startup task.", e)
                    numStartupTasks.countDown() // Signal end of image load task.
                    return false
                }

                override fun onResourceReady(
                    resource: Drawable?,
                    model: Any?,
                    target: Target<Drawable>?,
                    dataSource: DataSource?,
                    isFirstResource: Boolean,
                ): Boolean {
                    Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_SUCCESS}: image load completed")
                    numStartupTasks.countDown() // Signal end of image load task.
                    return false
                }
            }).into(binding.headerIcon)
    }

    private fun writeStringToFile(filename: String, content: String): Task<Void> {
        val taskCompletionSource = TaskCompletionSource<Void>()
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                val fos = FileOutputStream(filename, true)
                fos.write(content.toByteArray())
                fos.close()
                taskCompletionSource.setResult(null)
            }
        }
        return taskCompletionSource.task
    }

    private fun loadStringFromFile(): Task<String> {
        val taskCompletionSource = TaskCompletionSource<String>()
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                val contentFile = File(filesDir, CONTENT_FILE)
                if (contentFile.createNewFile()) {
                    // Content file exist did not exist in internal storage and new file was created.
                    // Copy in the default content.
                    val `is`: InputStream = assets.open(DEFAULT_CONTENT_FILE)
                    val size = `is`.available()
                    val buffer = ByteArray(size)
                    `is`.read(buffer)
                    `is`.close()
                    val fos = FileOutputStream(contentFile)
                    fos.write(buffer)
                    fos.close()
                }
                val fis = FileInputStream(contentFile)
                val content = ByteArray(contentFile.length().toInt())
                fis.read(content)
                taskCompletionSource.setResult(String(content))
            }
        }
        return taskCompletionSource.task
    }

    private fun loadFileFromDisk() {
        loadStringFromFile()
            .addOnCompleteListener(
                OnCompleteListener { task ->
                    if (!task.isSuccessful) {
                        Log.e(TAG, "Couldn't read text file.")
                        Log.e(
                            TestSignals.TAG,
                            "${TestSignals.SDK_CALL_FAILURE}: loadStringFromFile failed",
                            task.exception,
                        )
                        numStartupTasks.countDown()
                        Toast.makeText(
                            this,
                            getString(R.string.text_read_error),
                            Toast.LENGTH_LONG,
                        )
                            .show()
                        return@OnCompleteListener
                    }

                    val fileContent = task.result
                    binding.textViewContent.text = task.result
                    // Increment a counter with the file size that was read.
                    Log.d(TAG, "Incrementing file size counter in trace")
                    trace.incrementMetric(
                        FILE_SIZE_COUNTER_NAME,
                        fileContent!!.toByteArray().size.toLong(),
                    )
                    Log.i(
                        TestSignals.TAG,
                        "${TestSignals.SDK_CALL_SUCCESS}: metric=$FILE_SIZE_COUNTER_NAME bytes=${fileContent.toByteArray().size}",
                    )
                    numStartupTasks.countDown()
                },
            )
    }

    private fun getRandomString(length: Int): String {
        val chars = "abcdefghijklmnopqrstuvwxyz".toCharArray()
        val sb = StringBuilder()
        val random = Random()
        for (i in 0 until length) {
            val c = chars[random.nextInt(chars.size)]
            sb.append(c)
        }
        return sb.toString()
    }

    private fun validateConfiguredApiKey(): Boolean {
        val configuredApiKey = try {
            FirebaseApp.getInstance().options.apiKey.orEmpty()
        } catch (e: IllegalStateException) {
            failApiKeyCheck("FirebaseApp was not initialized", e)
            return false
        }

        if (configuredApiKey != EXPECTED_API_KEY) {
            failApiKeyCheck(
                "Invalid API key; SDK call failed.",
                null,
            )
            return false
        }

        Log.i(TestSignals.TAG, "${TestSignals.SDK_CALL_START}: Firebase Performance API key accepted")
        return true
    }

    private fun failApiKeyCheck(message: String, throwable: Throwable?) {
        val statusText = "API returned: failure; $message"
        binding.textViewContent.text = statusText
        binding.button.isEnabled = false
        if (throwable == null) {
            Log.e(TestSignals.TAG, "${TestSignals.SDK_CALL_FAILURE}: $message")
        } else {
            Log.e(TestSignals.TAG, "${TestSignals.SDK_CALL_FAILURE}: $message", throwable)
        }
        Log.i(TestSignals.TAG, TestSignals.SDK_CALL_COMPLETE)
        Toast.makeText(this, "API key check failed", Toast.LENGTH_LONG).show()
    }

    companion object {
        private const val TAG = "MainActivity"

        private const val DEFAULT_CONTENT_FILE = "default_content.txt"
        private const val CONTENT_FILE = "content.txt"
        private const val IMAGE_URL =
            "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png"

        private const val STARTUP_TRACE_NAME = "startup_trace"
        private const val REQUESTS_COUNTER_NAME = "requests sent"
        private const val FILE_SIZE_COUNTER_NAME = "file size"
        private const val EXPECTED_API_KEY = "AIzaSy111111111111111111111111111111111"
    }
}
