use anyhow::anyhow;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use std::net::{UdpSocket, SocketAddr};

/// 跳过HTTP头部
pub async fn skip_http_headers(stream: &mut TcpStream) -> anyhow::Result<()> {
    let mut buffer = [0u8; 1024];
    let mut total_read = 0;
    
    loop {
        let n = stream.peek(&mut buffer[total_read..]).await?;
        if n == 0 {
            return Err(anyhow!("连接关闭"));
        }
        
        total_read += n;
        if total_read >= 4 {
            // 检查是否找到HTTP头部结束标记
            if let Some(pos) = find_http_end(&buffer[..total_read]) {
                // 跳过HTTP头部
                let mut temp_buffer = vec![0u8; pos];
                stream.read_exact(&mut temp_buffer).await?;
                break;
            }
        }
        
        if total_read >= buffer.len() {
            return Err(anyhow!("HTTP头部过长"));
        }
    }
    Ok(())
}

/// 查找HTTP头部结束位置
fn find_http_end(data: &[u8]) -> Option<usize> {
    // 查找 "\r\n\r\n" 或 "\n\n"
    for i in 0..data.len().saturating_sub(3) {
        if data[i..i+4] == [13, 10, 13, 10] { // "\r\n\r\n"
            return Some(i + 4);
        }
    }
    for i in 0..data.len().saturating_sub(1) {
        if data[i..i+2] == [10, 10] { // "\n\n"
            return Some(i + 2);
        }
    }
    None
}

/// 检测是否为HTTP请求
pub async fn is_http_request(stream: &mut TcpStream) -> bool {
    let mut peek_buf = [0u8; 1024];
    match stream.peek(&mut peek_buf).await {
        Ok(n) if n > 0 => {
            let data = &peek_buf[..n];
            // 检测是否以HTTP方法开头
            data.starts_with(b"GET ") || 
            data.starts_with(b"POST ") || 
            data.starts_with(b"PUT ") ||
            data.starts_with(b"DELETE ") ||
            data.starts_with(b"HEAD ") ||
            data.starts_with(b"OPTIONS ") ||
            data.starts_with(b"PATCH ")
        }
        _ => false
    }
}

/// 发送HTTP混淆请求 - 同步版本，用于UDP握手前发送
pub fn send_http_obfuscation_sync(
    socket: &UdpSocket,
    hostname: &str,
    addr: SocketAddr,
) -> std::io::Result<()> {
    let http_request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n\
         Accept: */*\r\n\
         \r\n",
        hostname
    );
    
    socket.send_to(http_request.as_bytes(), addr)?;
    std::thread::sleep(std::time::Duration::from_millis(32));
    Ok(())
} 
