use super::ValidationError;

pub fn valid_json(
    value: String,
    field_name: &str,
    parent_name: Option<&str>,
) -> Result<serde_json::Value, ValidationError> {
    match serde_json::from_str(&value) {
        Ok(x) => Ok(x),
        Err(_) => Err(ValidationError::Invalid {
            field: super::field_name(field_name, parent_name),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_json() {
        assert!(matches!(valid_json(String::from("[]"), "test", None), Ok(..)));

        assert!(matches!(
            valid_json(String::from("1: 1"), "test", None),
            Err(ValidationError::Invalid { .. })
        ));
    }
}
