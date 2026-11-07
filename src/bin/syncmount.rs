//! The only release binary: five lines from argv to `lib::run`.

fn main() -> std::process::ExitCode {
    syncmount::run()
}
