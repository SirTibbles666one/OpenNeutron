use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Email {
    pub from: String,
    pub to: Vec<String>,
    pub raw_data: Vec<u8>,
    pub content: String,
    /// Every header, in arrival order, including duplicates.
    ///
    /// A map was the wrong shape: it silently dropped the second and later
    /// `Received:` lines (the delivery trail), and it had nowhere to put a
    /// folded continuation, so a long encoded Subject was truncated mid-word.
    pub headers: Vec<(String, String)>,
    
    
    pub dkim_status: String,
    pub is_e2ee: bool,
}

impl Email {
    pub fn new() -> Self {
        Email {
            from: String::new(),
            to: Vec::new(),
            raw_data: Vec::new(),
            content: String::new(),
            headers: Vec::new(),
            dkim_status: String::new(),
            is_e2ee: false,
        }
    }

    #[allow(dead_code)]
    /// The first value for a header name, matched without regard to case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every value for a header name, in arrival order.
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    pub fn to_string(&self) -> String {
        let mut email_string = "=================\r\n".to_string();
        email_string.push_str(&format!("From: {}\r\n", self.from));
        for recipient in &self.to {
            email_string.push_str(&format!("To: {}\r\n", recipient));
        }
        email_string.push_str(&format!("Headers: \r\n"));
        for (key, value) in &self.headers {
            email_string.push_str(&format!("{}: {}\r\n", key, value));
        }
        email_string.push_str(&format!("\r\n{}", self.content));
        email_string.push_str("=================\r\n");
        return email_string;
    }
}
