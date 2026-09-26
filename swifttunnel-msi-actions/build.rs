fn main() {
    // Windows Installer loads this DLL before the application is installed.
    // Its ABI passes MSI handles, not allocations owned by the CRT.
    static_vcruntime::metabuild();
}
