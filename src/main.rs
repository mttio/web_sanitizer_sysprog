use crate::cli_application::cli;

mod cli_application;
mod sanitizer_engine;






#[tokio::main]
async fn main() {
    println!("======= WELCOME TO THE WEB SANITIZER CLI INTERFACE =======");

    //run cli application
    let _ = cli::run().await; 

    println!("======================== GOODBYE =========================");
}
