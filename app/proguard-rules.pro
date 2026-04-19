# Keep VLESS config model for Gson serialization
-keep class com.musicses.vlessvpn.app.VlessConfig { *; }

# Keep OkHttp + Okio
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }

# Keep Gson
-keepattributes Signature
-keepattributes *Annotation*
-dontwarn sun.misc.**
-keep class com.google.gson.** { *; }

# Keep native method names
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep tun2socks JNI class
-keep class com.musicses.vlessvpn.Tun2Socks { *; }
-keep class com.musicses.vlessvpn.Tun2Socks$LogLevel { *; }
