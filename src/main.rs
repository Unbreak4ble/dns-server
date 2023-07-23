
mod domain_handler;
mod dns;
mod dns_server;
mod net;

#[tokio::main]
async fn main() {
    /* 
     * modify run_server() IP argument to run at specific network interface. For example:
     * 127.0.0.1 for loopback interface
     * 192.168.x.x/16 for gateway interface
     */
    dns_server::run_server(String::from("192.168.18.243")).await;
}
