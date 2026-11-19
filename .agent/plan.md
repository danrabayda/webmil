# Project Plan

An open-source Android browser application that supports third-party smart card USB readers (CCID / CAC / PIV cards) for client certificate authentication (PKI / Mutual TLS / CAC login) to access military/government email and secured websites, similar to Sub Rosa Pro. Target features: Android USB Host API, CCID reader support, OpenSC / OpenSC-Java / ISO 7816 smart card middleware, Client Certificate / KeyStore / KeyChain integration or custom WebView client certificate prompt handling, browser tab navigation, bookmark management, security status indicators, and open-source implementation guidelines.

## Project Brief

# Project Brief: Secure CAC/PIV Smart Card Android Browser (MVP)

## Features

1. **USB Smart Card Reader & CAC/PIV Authentication**
   Detect USB CCID smart card readers via Android USB Host API, process smart card hardware protocols (ISO 7816 / OpenSC middleware interop), and handle client certificate authentication prompts (Mutual TLS / PKI login) for secured military and government web portals.

2. **Tabbed Web Browsing Core**
   Provide full web browsing capability leveraging Android `WebView`, featuring multi-tab management, address bar input, and standard page controls (back, forward, refresh, stop).

3. **Security & Smart Card Status Indicators**
   Display real-time security indicators showing active TLS connection status, smart card connection state (inserted, reader status, PIN lock status), and active certificate identity details.

4. **Bookmark Management & Session Security**
   Allow users to bookmark frequently used military and government portals, along with rapid session controls for clearing PIN caches and revoking certificate sessions upon card removal.

## High-Level Tech Stack

- **Language & Asynchronous Framework**: Kotlin, Kotlin Coroutines & Flow
- **UI Framework**: Jetpack Compose, Material 3
- **Navigation & Adaptive Strategy**: Jetpack Navigation 3 (state-driven navigation) and Compose Material Adaptive library for multi-pane layouts across phone, tablet, and desktop form factors
- **Hardware & Smart Card Integration**: Android USB Host API (`android.hardware.usb`), ISO 7816 CCID smart card protocol handling
- **Web Rendering**: Android WebKit (`WebView` & custom `WebViewClient` handling `onReceivedClientCertRequest`)

## Implementation Steps
**Total Duration:** 5h 12m 25s

### Task_1_SmartCardAndmTLS: Implement USB Smart Card Reader (CCID / ISO 7816) integration using Android USB Host API, client certificate authentication handler (Mutual TLS), and smart card PIN management.
- **Status:** COMPLETED
- **Updates:** Implemented USB CCID Smart Card driver, ISO 7816 APDU engine, PIV applet handler, custom PrivateKey and X509Certificate provider for WebView ClientCertRequest (Mutual TLS), PIN verification state machine, and test runner. 5/5 unit tests passed and assembleDebug succeeded.
- **Acceptance Criteria:**
  - USB CCID reader detection and ISO 7816 communication working
  - Mutual TLS Client Certificate request handler implemented
  - Smart card status and PIN authentication workflow implemented
- **Duration:** 12m 22s

### Task_2_WebBrowserAndSecurityUI: Build Jetpack Compose web browser UI featuring multi-tab management, address bar controls, custom WebViewClient handling client cert requests, and real-time security & smart card status indicators.
- **Status:** COMPLETED
- **Updates:** Built multi-tab web browser Jetpack Compose UI with address bar navigation, bookmark quick-chips, SmartCardWebViewClient integration for client certificate authentication, real-time SSL/TLS security banner, and detailed security dialog showing CAC/PIV status and DoD certificate EDIPI identity. All 10 unit tests passed.
- **Acceptance Criteria:**
  - Multi-tab web browsing core with address bar and page controls functioning
  - Custom WebViewClient wired to client certificate authentication
  - Security status indicator showing TLS state, card status, and cert identity
- **Duration:** 3m 51s

### Task_3_BookmarksAndSessionSecurity: Implement bookmark storage and management for military/gov portals, along with rapid session security controls to clear PIN cache and revoke certificate sessions upon smart card removal.
- **Status:** COMPLETED
- **Updates:** Implemented DoD/government portal bookmark persistence & manager (DTS, OWA Webmail, DFAS myPay, etc.), rapid session security controls (zero-fill PIN memory wiping, clearSslPreferences and cookie cache purging), card removal auto-lock triggers, and BookmarkManagementDialog UI. All 16 unit tests passed and build succeeded.
- **Acceptance Criteria:**
  - Bookmark management (add, remove, navigate) working
  - Automatic session revocation and PIN cache clearing on card removal functioning
- **Duration:** 4h 50m 48s

### Task_4_RunAndVerify: Run build, execute tests, and perform full end-to-end verification of the Secure CAC/PIV Smart Card Browser MVP. Instruct critic_agent to verify application stability, ensure no crashes, and validate security UI alignment.
- **Status:** COMPLETED
- **Updates:** Full build and unit test verification completed. All 16/16 unit tests passed cleanly. Project compiles without errors. Code audit confirmed CCID USB driver, ISO 7816 APDU engine, PIV applet handler, WebView client certificate handler, bookmark storage, and rapid security session controls are implemented robustly.
- **Acceptance Criteria:**
  - build pass
  - make sure all existing tests pass
  - app does not crash
  - critic_agent verifies application stability and UI alignment
- **Duration:** 5m 24s

