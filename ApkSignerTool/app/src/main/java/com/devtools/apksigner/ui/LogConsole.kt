package com.devtools.apksigner.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp

@Composable
fun LogConsole(
    logContent: String,
    modifier: Modifier = Modifier
) {
    // 自动滚动到底部状态
    val scrollState = rememberScrollState()
    
    LaunchedEffect(logContent) {
        // 当日志更新时，自动滚动到最新一行
        scrollState.animateScrollTo(scrollState.maxValue)
    }

    Column(modifier = modifier) {
        Text(
            text = "运行日志 (长按可复制)",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        OutlinedTextField(
            value = logContent,
            onValueChange = {}, // 只读模式，禁止用户输入
            readOnly = true,
            textStyle = MaterialTheme.typography.bodySmall.copy(
                fontFamily = FontFamily.Monospace // 使用等宽字体，对齐日志更清晰
            ),
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 200.dp, max = 400.dp)
                .verticalScroll(scrollState),
            placeholder = { Text("等待任务执行...") },
            minLines = 8,
            maxLines = 20
        )
    }
}
