package net.swifttunnel.mobile

import java.io.IOException
import java.util.concurrent.TimeUnit
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response

class RelayCatalogClient(
    private val http: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(4, TimeUnit.SECONDS)
        .readTimeout(4, TimeUnit.SECONDS)
        .callTimeout(10, TimeUnit.SECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .retryOnConnectionFailure(false)
        .build(),
) {
    fun load(callback: (Result<List<RelayRegion>>) -> Unit): Call {
        val request = Request.Builder()
            .url("https://www.swifttunnel.net/api/vpn/servers")
            .header("Accept", "application/json")
            .header("User-Agent", "SwiftTunnel-Android/0.1.0-dev")
            .build()
        return http.newCall(request).also { call ->
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    callback(Result.failure(e))
                }

                override fun onResponse(call: Call, response: Response) {
                    val result = runCatching {
                        response.use {
                            if (!it.isSuccessful) throw IOException("Catalog unavailable")
                            val body = it.body ?: throw IOException("Missing catalog")
                            if (body.contentLength() > RelayCatalog.MAX_BYTES) {
                                throw IOException("Catalog too large")
                            }
                            val source = body.source()
                            // Bound decompressed data too, including chunked responses.
                            source.request(RelayCatalog.MAX_BYTES.toLong() + 1)
                            if (source.buffer.size > RelayCatalog.MAX_BYTES) {
                                throw IOException("Catalog too large")
                            }
                            RelayCatalog.parse(source.readUtf8())
                        }
                    }
                    callback(result)
                }
            })
        }
    }
}
