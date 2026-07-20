$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$SdkRoot = Join-Path $Root 'tools\android-sdk'
$KeyStoreDir = Join-Path $Root 'keystore'
$KeyStore = Join-Path $KeyStoreDir 'dexdumper-release.jks'
$StorePass = 'dexdumper123'
$KeyAlias = 'dexdumper'
$KeyPass = 'dexdumper123'

New-Item -ItemType Directory -Force $KeyStoreDir | Out-Null
if (!(Test-Path $KeyStore)) {
    keytool -genkeypair -v -keystore $KeyStore -storepass $StorePass -keypass $KeyPass -alias $KeyAlias -keyalg RSA -keysize 2048 -validity 36500 -dname "CN=DexDumper, OU=CTF, O=CTF, L=Local, ST=Local, C=US"
}

$env:ANDROID_HOME = $SdkRoot
$env:ANDROID_SDK_ROOT = $SdkRoot
$env:PATH = (Join-Path $Root 'tools\gradle-8.10.2\bin') + ';' + (Join-Path $SdkRoot 'platform-tools') + ';' + $env:PATH
& (Join-Path $Root 'tools\gradle-8.10.2\bin\gradle.bat') :app:assembleRelease `
  "-PRELEASE_STORE_FILE=$KeyStore" `
  "-PRELEASE_STORE_PASSWORD=$StorePass" `
  "-PRELEASE_KEY_ALIAS=$KeyAlias" `
  "-PRELEASE_KEY_PASSWORD=$KeyPass"

$DistDir = Join-Path $Root 'dist'
New-Item -ItemType Directory -Force $DistDir | Out-Null
Copy-Item -Force (Join-Path $Root 'app\build\outputs\apk\release\app-release.apk') (Join-Path $DistDir 'DexDumper-release.apk')
Get-FileHash (Join-Path $DistDir 'DexDumper-release.apk') -Algorithm SHA256
