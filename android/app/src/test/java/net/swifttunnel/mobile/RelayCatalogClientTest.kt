package net.swifttunnel.mobile

import java.io.ByteArrayOutputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPOutputStream
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import okio.Buffer
import org.junit.Assert.*
import org.junit.Test

class RelayCatalogClientTest {
    private fun client(server: MockWebServer, timeoutMs: Long = 2_000) = RelayCatalogClient(
        OkHttpClient.Builder()
            .callTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            .followRedirects(false)
            .retryOnConnectionFailure(false)
            .addInterceptor { chain ->
                chain.proceed(chain.request().newBuilder().url(server.url("/api/vpn/servers")).build())
            }.build(),
    )

    private fun read(server: MockWebServer): Result<List<RelayRegion>> {
        val result = CompletableFuture<Result<List<RelayRegion>>>()
        client(server).load { result.complete(it) }
        return result.get(5, TimeUnit.SECONDS)
    }

    @Test fun readsCatalogAndDoesNotSendCredentials() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setBody("""{"servers":[]}"""))
            assertTrue(read(server).isSuccess)
            val request = server.takeRequest(1, TimeUnit.SECONDS)!!
            assertEquals("/api/vpn/servers", request.path)
            assertNull(request.getHeader("Authorization"))
            assertNull(request.getHeader("Cookie"))
        }
    }

    @Test fun serverFailureIsNotAnEmptySuccess() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(503).setBody("{}"))
            assertTrue(read(server).isFailure)
        }
    }

    @Test fun redirectDoesNotFollowAnotherHost() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "http://127.0.0.1:1/"))
            assertTrue(read(server).isFailure)
            assertEquals(1, server.requestCount)
        }
    }

    @Test fun rejectsOversizedChunkedBodyWithoutContentLength() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setChunkedBody("x".repeat(RelayCatalog.MAX_BYTES + 1), 1024))
            assertTrue(read(server).isFailure)
        }
    }

    @Test fun rejectsOversizedDecompressedBody() {
        MockWebServer().use { server ->
            val bytes = ByteArrayOutputStream()
            GZIPOutputStream(bytes).use { it.write(ByteArray(RelayCatalog.MAX_BYTES + 1) { 32 }) }
            server.enqueue(MockResponse().setHeader("Content-Encoding", "gzip")
                .setBody(Buffer().write(bytes.toByteArray())))
            assertTrue(read(server).isFailure)
        }
    }

    @Test fun unresponsiveRequestIsBounded() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
            val result = CompletableFuture<Result<List<RelayRegion>>>()
            client(server, 150).load { result.complete(it) }
            assertTrue(result.get(3, TimeUnit.SECONDS).isFailure)
        }
    }

    @Test fun screenOwnerCanCancelPendingNetworkRequest() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
            val result = CompletableFuture<Result<List<RelayRegion>>>()
            val call = client(server).load { result.complete(it) }
            assertNotNull(server.takeRequest(1, TimeUnit.SECONDS))
            call.cancel()
            assertTrue(result.get(3, TimeUnit.SECONDS).isFailure)
            assertTrue(call.isCanceled())
        }
    }
}
