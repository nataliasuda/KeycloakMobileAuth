package com.example.keycloakmobileauth
import android.annotation.SuppressLint
import android.net.Uri
import android.util.Log
import net.openid.appauth.Preconditions
import net.openid.appauth.connectivity.ConnectionBuilder
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyManagementException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * An example implementation of [net.openid.appauth.connectivity.ConnectionBuilder] that permits connecting to http
 * links, and ignores certificates for https connections. *THIS SHOULD NOT BE USED IN PRODUCTION
 * CODE*. It is intended to facilitate easier testing of AppAuth against development servers
 * only.
 */
class ConnectionBuilderForTesting private constructor() : ConnectionBuilder {
    @Throws(IOException::class)
    override fun openConnection(uri: Uri): HttpURLConnection {
        Preconditions.checkNotNull<Uri?>(uri, "url must not be null")
        Preconditions.checkArgument(
            HTTP == uri.getScheme() || HTTPS == uri.getScheme(),
            "scheme or uri must be http or https"
        )
        val conn = URL(uri.toString()).openConnection() as HttpURLConnection
        conn.setConnectTimeout(CONNECTION_TIMEOUT_MS)
        conn.setReadTimeout(READ_TIMEOUT_MS)
        conn.setInstanceFollowRedirects(false)

        if (conn is HttpsURLConnection && TRUSTING_CONTEXT != null) {
            val httpsConn = conn
            httpsConn.setSSLSocketFactory(TRUSTING_CONTEXT.getSocketFactory())
            httpsConn.setHostnameVerifier(ANY_HOSTNAME_VERIFIER)
        }

        return conn
    }

    companion object {
        val INSTANCE: ConnectionBuilderForTesting = ConnectionBuilderForTesting()

        private const val TAG = "ConnBuilder"

        private val CONNECTION_TIMEOUT_MS = TimeUnit.SECONDS.toMillis(15).toInt()
        private val READ_TIMEOUT_MS = TimeUnit.SECONDS.toMillis(10).toInt()

        private const val HTTP = "http"
        private const val HTTPS = "https"

        @SuppressLint("TrustAllX509TrustManager", "CustomX509TrustManager")
        private val ANY_CERT_MANAGER: Array<TrustManager> =
            arrayOf<TrustManager>(object : X509TrustManager {
                override fun getAcceptedIssuers(): Array<X509Certificate?>? {
                    return null
                }

                override fun checkClientTrusted(
                    certs: Array<X509Certificate?>?,
                    authType: String?
                ) {
                }

                override fun checkServerTrusted(
                    certs: Array<X509Certificate?>?,
                    authType: String?
                ) {
                }
            }
            )

        @SuppressLint("BadHostnameVerifier")
        private val ANY_HOSTNAME_VERIFIER: HostnameVerifier = object : HostnameVerifier {
            override fun verify(hostname: String?, session: SSLSession?): Boolean {
                return true
            }
        }

        private val TRUSTING_CONTEXT: SSLContext?

        init {
            var context: SSLContext?
            try {
                context = SSLContext.getInstance("SSL")
            } catch (e: NoSuchAlgorithmException) {
                Log.e("ConnBuilder", "Unable to acquire SSL context")
                context = null
            }

            var initializedContext: SSLContext? = null
            if (context != null) {
                try {
                    context.init(null, ANY_CERT_MANAGER, SecureRandom())
                    initializedContext = context
                } catch (e: KeyManagementException) {
                    Log.e(TAG, "Failed to initialize trusting SSL context")
                }
            }

            TRUSTING_CONTEXT = initializedContext
        }
    }
}