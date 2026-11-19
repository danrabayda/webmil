package com.example.webmil

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import com.example.webmil.ui.SmartCardViewModel
import com.example.webmil.ui.screens.SmartCardHomeScreen
import com.example.webmil.ui.theme.WebmilTheme

class MainActivity : ComponentActivity() {

    private val smartCardViewModel: SmartCardViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            WebmilTheme {
                val uiState by smartCardViewModel.uiState.collectAsState()
                SmartCardHomeScreen(
                    uiState = uiState,
                    viewModel = smartCardViewModel
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        smartCardViewModel.scanUsbDevices()
    }
}
