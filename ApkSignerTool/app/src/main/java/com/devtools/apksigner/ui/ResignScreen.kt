package com.devtools.apksigner.ui

import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.devtools.apksigner.core.ApkResigner
import com.devtools.apksigner.core.FileUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import com.devtools.apksigner.ui.LogConsole


@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResignScreen(navController: NavController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    var apkUri by remember { mutableStateOf<Uri?>(null) }
    var ksUri by remember { mutableStateOf<Uri?>(null) }
    var alias by remember { mutableStateOf("mykey") }
    var password by remember { mutableStateOf("123456") }
    var isLoading by remember { mutableStateOf(false) }
    // 🆕 新增日志状态
    var logText by remember { mutableStateOf("") }
    
    // 🆕 封装一个追加日志的方法（自动带时间戳）
    val appendLog: (String) -> Unit = { msg ->
        val time = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
            .format(java.util.Date())
        logText += "[$time] $msg\n"
    }

    val apkPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { apkUri = it }
    val ksPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { ksUri = it }
    
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")) { outUri: Uri? ->
    
    // 🆕 修改 saver 回调，将 try-catch 中的信息写入日志
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")) { outUri: Uri? ->
        if (apkUri != null && ksUri != null && outUri != null) {
            scope.launch {
                isLoading = true
                appendLog("开始重签名任务...")
                
                withContext(Dispatchers.IO) {
                    try {
                        appendLog("正在拷贝原始 APK 到临时目录...")
                        val inApk = FileUtils.uriToTempFile(context, apkUri!!, "input.apk")
                        
                        appendLog("正在加载证书文件...")
                        val ksFile = FileUtils.uriToTempFile(context, ksUri!!, "temp.p12")
                        val outApk = File(context.cacheDir, "output.apk")
                        
                        appendLog("调用 apksig 执行 V1+V2+V3 签名...")
                        ApkResigner.resign(inApk, outApk, ksFile, password.toCharArray(), alias)
                        
                        appendLog("正在将签名后的 APK 写入目标路径...")
                        FileUtils.tempFileToUri(context, outApk, outUri!!)
                        
                        inApk.delete(); ksFile.delete(); outApk.delete()
                        
                        withContext(Dispatchers.Main) {
                            appendLog("✅ 重签名成功！文件大小: ${outUri.let { 
                                context.contentResolver.openFileDescriptor(it, "r")?.use { fd -> fd.statSize } ?: 0L 
                            } / 1024} KB")
                        }
                    } catch (e: Exception) {
                        // 🔥 捕获完整堆栈并输出到日志面板
                        val stackTrace = e.stackTraceToString().take(500) // 限制长度防止OOM
                        withContext(Dispatchers.Main) {
                            appendLog("❌ 签名失败!")
                            appendLog("异常类型: ${e.javaClass.simpleName}")
                            appendLog("错误详情: ${e.message}")
                            appendLog("堆栈追踪:\n$stackTrace")
                        }
                    } finally {
                        withContext(Dispatchers.Main) { isLoading = false }
                    }
                }
            }
        } else {
            appendLog("⚠️ 用户取消了保存操作")
        }
    }



    Scaffold(topBar = { TopAppBar(title = { Text("APK 重签名") }, navigationIcon = { TextButton(onClick = { navController.popBackStack() }) { Text("返回") } }) }) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp)) {
            Button(onClick = { apkPicker.launch(arrayOf("application/vnd.android.package-archive")) }, modifier = Modifier.fillMaxWidth()) {
                Text(if (apkUri == null) "选择原始 APK" else "已选择 APK")
            }
            Spacer(Modifier.height(16.dp))
            Button(onClick = { ksPicker.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
                Text(if (ksUri == null) "选择证书文件 (.jks/.p12)" else "已选择证书")
            }
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(value = alias, onValueChange = { alias = it }, label = { Text("别名") }, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(value = password, onValueChange = { password = it }, label = { Text("密码") }, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(32.dp))
            Button(
                onClick = { saver.launch("resigned-app.apk") },
                enabled = !isLoading && apkUri != null && ksUri != null,
                modifier = Modifier.fillMaxWidth().height(50.dp)
            ) {
                if (isLoading) CircularProgressIndicator(modifier = Modifier.size(24.dp)) else Text("选择输出路径并签名")
            }
            Spacer(Modifier.weight(1f)) // 将日志面板推到底部
            
            // 🆕 放置日志控制台
            LogConsole(
                logContent = logText,
                modifier = Modifier.fillMaxWidth()
            )

        }
    }
}
