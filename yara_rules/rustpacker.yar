rule RustPacker_Signature
{
    meta:
        description = "Detects Windows binaries packed with RustPacker"
        author = "Huy"
        reference = "https://github.com/Nariod/RustPacker"
        version = "1.0"

    strings:
        $rs_runtime = "core::fmt::Formatter::write_str" ascii
        $crt_static = "crt-static" ascii
        $release_path = "target/x86_64-pc-windows-gnu/release" ascii
        $aes_init = { 0f 00 0f 00 ?? ?? ?? ?? 41 0f b6 ?? }  // generic pattern in RustPacker AES init

    condition:
        uint16(0) == 0x5A4D and // MZ header (Windows PE)
        2 of ($rs_runtime, $crt_static, $release_path, $aes_init)
}


rule RustPacker_Generic
{
    meta:
        description = "Detects PE files packed with Rust-based packer (e.g., RustPacker)"
        author = "Huy2"
        reference = "https://github.com/Nariod/RustPacker"
        version = "1.0"

    strings:
        $rust_marker1 = "AWAVAUATVWUSH" wide ascii
        $rust_marker2 = "modnarod" ascii
        $rust_marker3 = "arenegyl" ascii
        $rust_marker4 = "setybdet" ascii
        $rust_dbg1 = "library\\alloc\\src\\raw_vec\\mod.rs" ascii
        $rust_dbg2 = "library\\core\\src\\panicking.rs" ascii
        $rust_dbg3 = "RUST_MIN_STACK" ascii
        $obfuscate1 = "[]_^A\\A]A^A_" ascii
        $obfuscate2 = "[_^A^]" ascii

    condition:
        uint16(0) == 0x5A4D and // MZ header
        filesize < 100MB and
        3 of ($rust_marker*) and
        2 of ($rust_dbg*) and
        1 of ($obfuscate*)
}



