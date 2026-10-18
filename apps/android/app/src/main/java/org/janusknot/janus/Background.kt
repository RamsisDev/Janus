package org.janusknot.janus

import android.app.Application
import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class JanusApplication : Application() {
    val model by lazy { AppModel(this) }

    override fun onCreate() {
        super.onCreate()
        TickWorker.schedule(this)
    }
}

/**
 * Wakes the app now and then to fetch, answer handshakes and send cover. There is no push by
 * default, so this is how messages arrive while the app is closed.
 */
class TickWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val model = (applicationContext as JanusApplication).model
        withContext(Dispatchers.Main) { model.wake() }
        return Result.success()
    }

    companion object {
        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<TickWorker>(15, TimeUnit.MINUTES)
                .setConstraints(
                    Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
                )
                .build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork("tick", ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}
