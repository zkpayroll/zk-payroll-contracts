pub fn normalize_symbol(symbol: &str) -> Option<String> {
    let t = symbol.trim();
    if t.is_empty() { None } else { Some(t.to_uppercase()) }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ok() { assert_eq!(normalize_symbol(" usd "), Some("USD".to_string())); }
    #[test]
    fn test_ok2() { assert_eq!(normalize_symbol("eth-usd"), Some("ETH-USD".to_string())); }
    #[test]
    fn test_fail_empty() { assert_eq!(normalize_symbol(" "), None); }
}