package net.swifttunnel.mobile

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import okhttp3.Call

data class CatalogState(
    val regions: List<RelayRegion> = emptyList(),
    val loading: Boolean = false,
    val failed: Boolean = false,
    val loadedAtMs: Long? = null,
)

class CatalogViewModel : ViewModel() {
    private val client = RelayCatalogClient()
    private val main = Handler(Looper.getMainLooper())
    private val mutableState = MutableLiveData(CatalogState())
    val state: LiveData<CatalogState> = mutableState
    private var pending: Call? = null
    private var generation = 0L

    init {
        refresh()
    }

    fun refresh() {
        if (mutableState.value!!.loading) return
        val attempt = ++generation
        mutableState.value = mutableState.value!!.copy(loading = true, failed = false)
        pending = client.load { result ->
            main.post {
                if (generation != attempt) return@post
                pending = null
                mutableState.value = result.fold(
                    onSuccess = { CatalogState(it, loadedAtMs = SystemClock.elapsedRealtime()) },
                    onFailure = {
                        mutableState.value!!.copy(loading = false, failed = true, loadedAtMs = null)
                    },
                )
            }
        }
    }

    override fun onCleared() {
        ++generation
        pending?.cancel()
        main.removeCallbacksAndMessages(null)
        super.onCleared()
    }
}
