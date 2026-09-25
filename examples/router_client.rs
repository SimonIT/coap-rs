extern crate coap;

// use coap::client::ObserveMessage;
use coap::router::extract::Json;
use coap::UdpCoAPClient;
// use std::io;
use std::io::ErrorKind;

#[tokio::main]
async fn main() {
    println!("GET url:");
    example_get().await;

    println!("POST data to url:");
    example_post().await;

    println!("GET url again:");
    example_get().await;
}

async fn example_get() {
    let url = "coap://127.0.0.1:5683/temperature?room=kitchen";
    println!("Client request: {}", url);

    match UdpCoAPClient::get(url).await {
        Ok(response) => {
            println!(
                "Server reply: {}",
                String::from_utf8(response.message.payload).unwrap()
            );
        }
        Err(e) => {
            match e.kind() {
                ErrorKind::WouldBlock => println!("Request timeout"), // Unix
                ErrorKind::TimedOut => println!("Request timeout"),   // Windows
                _ => println!("Request error: {:?}", e),
            }
        }
    }
}

async fn example_post() {
    let url = "coap://127.0.0.1:5683/temperature/kitchen";
    println!("Client request: {}", url);

    // The body is serialized to JSON automatically and the reply is decoded as a string.
    match UdpCoAPClient::post_typed::<_, String>(url, Json(21.0)).await {
        Ok(reply) => {
            println!("Server reply: {}", reply);
        }
        Err(e) => {
            match e.kind() {
                ErrorKind::WouldBlock => println!("Request timeout"), // Unix
                ErrorKind::TimedOut => println!("Request timeout"),   // Windows
                _ => println!("Request error: {:?}", e),
            }
        }
    }
}
