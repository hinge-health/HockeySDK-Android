package net.hockeyapp.android.utils;

import android.os.AsyncTask;

import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;

/**
 * <h3>Description</h3>
 *
 * Either calls execute or executeOnExecutor on an AsyncTask depending on the
 * API level.
 */
public class AsyncTaskUtils {


    public static void execute(AsyncTask<Void, ?, ?> asyncTask) {
        asyncTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
    }

}
