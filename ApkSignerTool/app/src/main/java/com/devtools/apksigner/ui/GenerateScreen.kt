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
import com.devtools.apksigner.core.FileUtils
import com.devtools.apksigner.core.KeystoreGenerator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GenerateScreen(navController: NavController) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var alias by remember { mutableStateOf("mykey") }
    var password by remember { mutableStateOf("123456") }
    var isLoading by remember { mutableStateOf(false) }

    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/x-pkcs12")) { uri: Uri? ->
        uri?.let {
            scope.launch {
                isLoading = true
                withContext(Dispatchers.IO) {
                    try {
                        val tempFile = File(context.cacheDir, "temp_generated.p12")
                        KeystoreGenerator.generate(tempFile, alias, password.toCharArray())
                        FileUtils.tempFileToUri(context, tempFile, it)
                        tempFile.delete()
                        withContext(Dispatchers.Main) {
                            Toast.makeText(context, "证书生成成功！", Toast.LENGTH_SHORT).show()
                            navController.popBackStack()
                        }
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) { Toast.makeText(context, "失败: ${e.message}", Toast.LENGTH_LONG).show() }
                    } finally { isLoading = false }
                }
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("生成证书") }, navigationIcon = { TextButton(onClick = { navController.popBackStack() }) { Text("返回") } }) }) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp)) {
            OutlinedTextField(value = alias, onValueChange = { alias = it }, label = { Text("别名 (Alias)") }, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(value = password, onValueChange = { password = it }, label = { Text("密码 (Password)") }, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(32.dp))
            Button(
                onClick = { saver.launch("my-release-key.p12") },
                enabled = !isLoading && alias.isNotBlank() && password.isNotBlank(),
                modifier = Modifier.fillMaxWidth().height(50.dp)
            ) {
                if (isLoading) CircularProgressIndicator(modifier = Modifier.size(24.dp)) else Text("选择保存路径并生成")
            }
        }
    }
}
