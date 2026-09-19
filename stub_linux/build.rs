// Link do stub sem CRT/libc; o entry point é `_start` definido no próprio binário.
// Os argumentos são aplicados apenas ao target final, não aos build scripts das dependências.
fn main() {
    println!("cargo:rustc-link-arg-bins=-nostartfiles");
    println!("cargo:rustc-link-arg-bins=-nodefaultlibs");
    println!("cargo:rustc-link-arg-bins=-static");
    println!("cargo:rustc-link-arg-bins=-no-pie");
    println!("cargo:rustc-link-arg-bins=-Wl,-e,_start");
}
