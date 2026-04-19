# Keep tun2socks JNI entry points
-keep class com.musicses.vlessvpn.Tun2Socks { *; }
-keep class com.musicses.vlessvpn.Tun2Socks$LogLevel { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
