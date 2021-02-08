#[macro_use]
#[cfg(test)]
macro_rules! asym_key_tests { () => {
        #[test]
        fn test_key_serialization() {
            run_serialization_test::<PublicKey, SecretKey, Engine>(get_test_case());
        }

        #[test]
        fn test_pri_key_to_pub_key() {
            run_pri_to_pub_test::<PublicKey, SecretKey, Engine>(get_test_case());
        }

        #[test]
        fn test_random_keys() {
            run_random_key_test::<PublicKey, SecretKey, Engine>(get_test_case());
        }

        #[test]
        fn test_shared_secret() {
            run_ecdh_test_case::<PublicKey, SecretKey, Engine>(get_test_case());
        }
    };}