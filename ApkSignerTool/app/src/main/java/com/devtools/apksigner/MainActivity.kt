package com.devtools.apksigner

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.devtools.apksigner.ui.GenerateScreen
import com.devtools.apksigner.ui.MainScreen
import com.devtools.apksigner.ui.ResignScreen
import com.devtools.apksigner.ui.theme.ApkSignerTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ApkSignerTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    val navController = rememberNavController()
                    NavHost(navController = navController, startDestination = "main") {
                        composable("main") { MainScreen(navController) }
                        composable("generate") { GenerateScreen(navController) }
                        composable("resign") { ResignScreen(navController) }
                    }
                }
            }
        }
    }
}
