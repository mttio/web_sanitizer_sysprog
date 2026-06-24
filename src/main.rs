use crate::cli_application::cli;

mod cli_application;
mod sanitizer_engine;

fn main() {
    println!("======= WELCOME TO THE WEB SANITIZER CLI INTERFACE =======");

    //run cli application
    if let Err(e) = cli::run() {
        eprintln!("Application error: {:?}", e);
    }

    println!("======================== GOODBYE =========================");
}
