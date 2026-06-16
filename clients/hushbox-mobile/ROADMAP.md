# hushbox-mobile — Roadmap

## Milestones

### 1. Proof of concept
Bootstrap a minimal working app using **Kivy** or **React Native + httpx**.
Send and receive a single encrypted message end-to-end via the relay.

### 2. hushbox-core integration
Import `hushbox-core` directly (Kivy/BeeWare Python runtime) or wrap it via FFI.
All encryption, key management, and relay transport logic reused from the shared package — no reimplementation.

### 3. QR scan with camera
Use the device camera to scan a contact's public-key QR code.
Parse the JSON payload (`{"public_key": "..."}`) and add the contact in one step.

### 4. Push notifications (FCM / APNs) as polling trigger
Instead of continuous background polling, receive a silent push notification (Firebase Cloud Messaging on Android, APNs on iOS) when a new message arrives on the relay.
The notification triggers a single poll to fetch and decrypt the message — no persistent connection required.

### 5. Biometric unlock
Gate access to the app and to Keychain/Keystore key operations behind biometric authentication (Face ID, Touch ID, or Android BiometricPrompt).
Private key is only accessible after a successful biometric check.
