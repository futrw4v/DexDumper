$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$SdkRoot = Join-Path $Root 'tools\android-sdk'
$env:ANDROID_HOME = $SdkRoot
$env:ANDROID_SDK_ROOT = $SdkRoot
$env:PATH = (Join-Path $Root 'tools\gradle-8.10.2\bin') + ';' + (Join-Path $SdkRoot 'platform-tools') + ';' + $env:PATH
& (Join-Path $Root 'tools\gradle-8.10.2\bin\gradle.bat') :app:assembleDebug
