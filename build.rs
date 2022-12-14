fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new("git").args(["rev-parse", "HEAD"]).output()?;
    let rev = String::from_utf8(output.stdout)?;
    println!("cargo:rustc-env=GIT_COMMIT_SHA={rev}");
    println!("cargo:rustc-rerun-if-changed=.git/HEAD");
    Ok(())
}
