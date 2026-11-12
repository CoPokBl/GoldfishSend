package app.goldfishsend.ui.components

import android.graphics.Bitmap
import android.util.Size
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Image
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

fun qrBitmap(text: String, dark: Color, light: Color): Bitmap {
    val m = QRCodeWriter().encode(
        text, BarcodeFormat.QR_CODE, 0, 0,
        mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 1),
    )
    val w = m.width
    val h = m.height
    val px = IntArray(w * h)
    val d = dark.toArgb()
    val l = light.toArgb()
    for (y in 0 until h) {
        for (x in 0 until w) {
            px[y * w + x] = if (m[x, y]) d else l
        }
    }
    return Bitmap.createBitmap(px, w, h, Bitmap.Config.ARGB_8888)
}

@Composable
fun QrImage(text: String, modifier: Modifier = Modifier, dark: Color = Color(0xFF1A120D), light: Color = Color.White) {
    val bmp = remember(text, dark, light) { qrBitmap(text, dark, light).asImageBitmap() }
    Image(bmp, contentDescription = "Your invite code", modifier = modifier, filterQuality = FilterQuality.None)
}

/** CameraX preview with ZXing QR decoding on the luminance plane. Calls [onResult] once. */
@Composable
fun QrScanner(modifier: Modifier = Modifier, onResult: (String) -> Unit) {
    val ctx = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current
    val done = remember { AtomicBoolean(false) }
    val executor = remember { Executors.newSingleThreadExecutor() }
    val reader = remember { QRCodeReader() }
    DisposableEffect(Unit) {
        onDispose { executor.shutdown() }
    }
    AndroidView(
        modifier = modifier,
        factory = { c ->
            val view = PreviewView(c).apply { scaleType = PreviewView.ScaleType.FILL_CENTER }
            val providerFuture = ProcessCameraProvider.getInstance(c)
            providerFuture.addListener({
                val provider = providerFuture.get()
                val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
                @Suppress("DEPRECATION")
                val analysis = ImageAnalysis.Builder()
                    .setTargetResolution(Size(1280, 720))
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                analysis.setAnalyzer(executor) { img -> analyze(img, reader, done, onResult, ctx) }
                runCatching {
                    provider.unbindAll()
                    provider.bindToLifecycle(lifecycle, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
                }
            }, ContextCompat.getMainExecutor(c))
            view
        },
    )
}

private fun analyze(img: ImageProxy, reader: QRCodeReader, done: AtomicBoolean, onResult: (String) -> Unit, ctx: android.content.Context) {
    try {
        if (done.get()) {
            return
        }
        val plane = img.planes[0]
        val buf = plane.buffer
        val data = ByteArray(buf.remaining())
        buf.get(data)
        val src = PlanarYUVLuminanceSource(data, plane.rowStride, img.height, 0, 0, img.width, img.height, false)
        val result = runCatching {
            reader.decode(BinaryBitmap(HybridBinarizer(src)), mapOf(DecodeHintType.TRY_HARDER to true))
        }.getOrNull()
        reader.reset()
        if (result != null && done.compareAndSet(false, true)) {
            ContextCompat.getMainExecutor(ctx).execute { onResult(result.text) }
        }
    } finally {
        img.close()
    }
}
