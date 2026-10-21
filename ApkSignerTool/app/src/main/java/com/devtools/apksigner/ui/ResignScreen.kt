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

    val apkPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { apkUri = it }
    val ksPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { ksUri = it }
    
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")) { outUri: Uri? ->
        if (apkUri != null && ksUri != null && outUri != null) {
            scope.launch {
                isLoading = true
                withContext(Dispatchers.IO) {
                    try {
                        val inApk = FileUtils.uriToTempFile(context, apkUri!!, "input.apk")
                        val ksFile = FileUtils.uriToTempFile(context, ksUri!!, "temp.p12")
                        val outApk = File(context.cacheDir, "output.apk")
                        
                        ApkResigner.resign(inApk, outApk, ksFile, password.toCharArray(), alias)
                        
                        FileUtils.tempFileToUri(context, outApk, outUri!!)
                        
                        inApk.delete(); ksFile.delete(); outApk.delete()
                        
                        withContext(Dispatchers.Main) {
                            Toast.makeText(context, "重签名成功！", Toast.LENGTH_SHORT).show()
                            navController.popBackStack()
                        }
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) { Toast.makeText(context, "签名失败: ${e.message}", Toast.LENGTH_LONG).show() }
                    } finally { isLoading = false }
                }
            }
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
        }
    }
}
