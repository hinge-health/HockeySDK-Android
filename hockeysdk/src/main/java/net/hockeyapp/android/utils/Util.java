package net.hockeyapp.android.utils;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Debug;
import android.provider.OpenableColumns;
import android.text.TextUtils;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;

import net.hockeyapp.android.R;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;

public class Util {
    private static final String APP_IDENTIFIER_PATTERN = "[0-9a-f]+";
    private static final int APP_IDENTIFIER_LENGTH = 32;
    private static final String APP_IDENTIFIER_KEY = "net.hockeyapp.android.appIdentifier";
    private static final String APP_SECRET_KEY = "net.hockeyapp.android.appSecret";
    private static final Pattern appIdentifierPattern = Pattern.compile(APP_IDENTIFIER_PATTERN, Pattern.CASE_INSENSITIVE);


    /**
     * Returns the given param URL-encoded.
     *
     * @param param a string to encode
     * @return the encoded param
     */
    public static String encodeParam(String param) {
        try {
            return URLEncoder.encode(param, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // UTF-8 should be available, so just in case
            HockeyLog.error("Failed to encode param " + param, e);
            return "";
        }
    }

    /**
     * Returns true if value is a valid email.
     *
     * @param value a string
     * @return true if value is a valid email
     */
    public static boolean isValidEmail(String value) {
        return !TextUtils.isEmpty(value) && android.util.Patterns.EMAIL_ADDRESS.matcher(value).matches();
    }

    /**
     * Returns true if the app runs on large or very large screens (i.e. tablets).
     *
     * @param context the context to use
     * @return true if the app runs on large or very large screens
     */
    public static Boolean runsOnTablet(Context context) {
        if (context != null) {
            Configuration configuration = context.getResources().getConfiguration();
            return (((configuration.screenLayout & Configuration.SCREENLAYOUT_SIZE_MASK) == Configuration.SCREENLAYOUT_SIZE_LARGE) ||
                    ((configuration.screenLayout & Configuration.SCREENLAYOUT_SIZE_MASK) == Configuration.SCREENLAYOUT_SIZE_XLARGE));
        }
        return false;
    }

    /**
     * Sanitizes an app identifier or throws an exception if it can't be sanitized.
     *
     * @param appIdentifier the app identifier to sanitize
     * @return the sanitized app identifier
     * @throws java.lang.IllegalArgumentException if the app identifier can't be sanitized because of unrecoverable input character errors
     */
    public static String sanitizeAppIdentifier(String appIdentifier) throws IllegalArgumentException {

        if (appIdentifier == null) {
            throw new IllegalArgumentException("App ID must not be null.");
        }

        String sAppIdentifier = appIdentifier.trim();

        Matcher matcher = appIdentifierPattern.matcher(sAppIdentifier);

        if (sAppIdentifier.length() != APP_IDENTIFIER_LENGTH) {
            throw new IllegalArgumentException("App ID length must be " + APP_IDENTIFIER_LENGTH + " characters.");
        } else if (!matcher.matches()) {
            throw new IllegalArgumentException("App ID must match regex pattern /" + APP_IDENTIFIER_PATTERN + "/i");
        }

        return sAppIdentifier;
    }

    /**
     * Retrieve the HockeyApp AppIdentifier from the Manifest
     *
     * @param context usually your Activity
     * @return the HockeyApp AppIdentifier
     */
    public static String getAppIdentifier(Context context) {
        String appIdentifier = getManifestString(context, APP_IDENTIFIER_KEY);
        if (TextUtils.isEmpty(appIdentifier)) {
            throw new IllegalArgumentException("HockeyApp app identifier was not configured correctly in manifest or build configuration.");
        }
        return appIdentifier;
    }

    /**
     * Retrieve the HockeyApp appSecret from the Manifest
     *
     * @param context usually your Activity
     * @return the HockeyApp appSecret
     */
    public static String getAppSecret(Context context) {
        return getManifestString(context, APP_SECRET_KEY);
    }

    public static String getManifestString(Context context, String key) {
        return getBundle(context).getString(key);
    }

    private static Bundle getBundle(Context context) {
        Bundle bundle;
        try {
            bundle = context.getPackageManager().getApplicationInfo(context.getPackageName(), PackageManager.GET_META_DATA).metaData;
        } catch (PackageManager.NameNotFoundException e) {
            throw new RuntimeException(e);
        }
        return bundle;
    }

    public static boolean isConnectedToNetwork(Context context) {
        try {
            ConnectivityManager connectivityManager = (ConnectivityManager) context.getApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
            if (connectivityManager != null) {
                NetworkInfo activeNetwork = connectivityManager.getActiveNetworkInfo();
                return activeNetwork != null && activeNetwork.isConnected();
            }
        } catch (Exception e) {
            HockeyLog.error("Exception thrown when check network is connected", e);
        }
        return false;
    }

    public static HttpsURLConnection openHttpsConnection(URL url) throws IOException {
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

        /*
         * Make sure we use TLS 1.2 when the device supports it but not enabled by default.
         * Don't hardcode TLS version when enabled by default to avoid unnecessary wrapping and
         * to support future versions of TLS such as say 1.3 without having to patch this code.
         *
         * TLS 1.2 was enabled by default only on Android 5.0:
         * https://developer.android.com/about/versions/android-5.0-changes#ssl
         * https://developer.android.com/reference/javax/net/ssl/SSLSocket#default-configuration-for-different-android-versions
         *
         * There is a problem that TLS 1.2 is still disabled by default on some Samsung devices
         * with API 21, so apply the rule to this API level as well.
         * See https://github.com/square/okhttp/issues/2372#issuecomment-244807676
         */
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.LOLLIPOP) {
            connection.setSSLSocketFactory(new TLS1_2SocketFactory());
        }
        return connection;
    }

    public static String getAppName(Context context) {
        PackageManager packageManager = context.getPackageManager();
        ApplicationInfo applicationInfo = null;
        try {
            applicationInfo = packageManager.getApplicationInfo(context.getApplicationInfo().packageName, 0);
        } catch (final PackageManager.NameNotFoundException ignored) {
        }
        return applicationInfo != null ? (String) packageManager.getApplicationLabel(applicationInfo)
                : context.getString(R.string.hockeyapp_crash_dialog_app_name_fallback);
    }

    /**
     * Sanitizes an app identifier and adds dashes to it so that it conforms to the instrumentation
     * key format of Application Insights.
     *
     * @param appIdentifier the app identifier to sanitize and convert
     * @return the converted appIdentifier
     * @throws java.lang.IllegalArgumentException if the app identifier can't be converted because
     *                                            of unrecoverable input character errors
     */
    public static String convertAppIdentifierToGuid(String appIdentifier) throws IllegalArgumentException {
        String sanitizedAppIdentifier= sanitizeAppIdentifier(appIdentifier);
        String guid = null;

        if (sanitizedAppIdentifier != null) {
            StringBuilder idBuf = new StringBuilder(sanitizedAppIdentifier);
            idBuf.insert(20, '-');
            idBuf.insert(16, '-');
            idBuf.insert(12, '-');
            idBuf.insert(8, '-');
            guid = idBuf.toString();
        }
        return guid;
    }

    public static String convertStreamToString(InputStream inputStream) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream), 1024);
        StringBuilder stringBuilder = new StringBuilder();

        String line;
        try {
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line).append('\n');
            }
        } catch (IOException e) {
            HockeyLog.error("Failed to convert stream to string", e);
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (Exception ignored) {
            }
        }
        return stringBuilder.toString();
    }


}
