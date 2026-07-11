package com.firebase.crash.attacker;

import android.content.Context;
import android.util.TypedValue;
import android.view.View;
import android.widget.TextView;

import androidx.annotation.StringRes;

import com.google.android.material.snackbar.Snackbar;

/**
 * Shared UI helpers for crash feedback (status area + Snackbar).
 */
public final class CrashFeedbackUi {

    private CrashFeedbackUi() {}

    public static void showSnackbar(View root, CharSequence message, int duration, Context context) {
        Snackbar snackbar = Snackbar.make(root, message, duration);
        TextView textView = snackbar.getView().findViewById(
                com.google.android.material.R.id.snackbar_text);
        textView.setTextSize(
                TypedValue.COMPLEX_UNIT_PX,
                context.getResources().getDimension(R.dimen.crash_snackbar_text_size));
        snackbar.show();
    }

    public static void showSnackbar(View root, @StringRes int messageResId, int duration, Context context) {
        showSnackbar(root, context.getString(messageResId), duration, context);
    }
}
