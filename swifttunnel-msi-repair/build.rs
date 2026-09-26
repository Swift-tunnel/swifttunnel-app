fn main() {
    // Recovery must work even when the VC redistributable is absent.
    static_vcruntime::metabuild();
}
