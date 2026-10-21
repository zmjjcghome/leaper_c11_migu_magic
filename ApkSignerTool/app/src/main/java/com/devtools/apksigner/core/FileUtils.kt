package com.devtools.apksigner.core

import android.content.Context
import android.net.Uri
import java.io.File
import java.io.FileOutputStream

object FileUtils {
    // 将 SAF 获取的 URI 拷贝到应用内部 cache 目录，供 apksig 读取
    fun uriToTempFile(context: Context, uri: Uri, fileName: String): File {
        val tempFile = File(context.cacheDir, fileName)
        context.contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(tempFile).use { output ->
                input.copyTo(output)
            }
        }
        return tempFile
    }

    // 将内部 cache 文件写回用户选择的 SAF URI
    fun tempFileToUri(context: Context, tempFile: File, uri: Uri) {
        context.contentResolver.openOutputStream(uri)?.use { output ->
            tempFile.inputStream().use { input ->
                input.copyTo(output)
            }
        }
    }
}
