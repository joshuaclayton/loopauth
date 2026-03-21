use crate::error::TokenStoreError;
use crate::token::TokenSet;
use async_trait::async_trait;

/// Persistent storage interface for [`TokenSet`] values.
///
/// Implement this trait to persist tokens across invocations (file, keychain,
/// database, etc.). [`crate::CliTokenClient`] does not manage storage - call
/// [`TokenStore::save`] with the [`crate::TokenSet`] returned by
/// [`crate::CliTokenClient::run_authorization_flow`].
///
/// # Example
///
/// ```no_run
/// use async_trait::async_trait;
/// use loopauth::{TokenSet, TokenStore, TokenStoreError};
/// use std::sync::Mutex;
///
/// struct MemoryStore(Mutex<Option<TokenSet>>);
///
/// #[async_trait]
/// impl TokenStore for MemoryStore {
///     async fn load(&self) -> Result<Option<TokenSet>, TokenStoreError> {
///         Ok(self.0.lock().unwrap().clone())
///     }
///
///     async fn save(&self, tokens: &TokenSet) -> Result<(), TokenStoreError> {
///         *self.0.lock().unwrap() = Some(tokens.clone());
///         Ok(())
///     }
///
///     async fn clear(&self) -> Result<(), TokenStoreError> {
///         *self.0.lock().unwrap() = None;
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait TokenStore: Send + Sync {
    /// Load the stored [`TokenSet`], returning `Ok(None)` if none is persisted.
    ///
    /// # Errors
    ///
    /// Returns [`TokenStoreError`] on I/O or deserialization failure.
    async fn load(&self) -> Result<Option<TokenSet>, TokenStoreError>;

    /// Persist a [`TokenSet`], overwriting any previously stored value.
    ///
    /// # Errors
    ///
    /// Returns [`TokenStoreError`] on I/O or serialization failure.
    async fn save(&self, tokens: &TokenSet) -> Result<(), TokenStoreError>;

    /// Remove the stored [`TokenSet`].
    ///
    /// # Errors
    ///
    /// Returns [`TokenStoreError`] on I/O failure.
    async fn clear(&self) -> Result<(), TokenStoreError>;
}

#[cfg(test)]
mod tests {
    use super::TokenStore;
    use crate::error::TokenStoreError;
    use crate::token::TokenSet;
    use std::time::{Duration, SystemTime};

    struct NoopStore;

    #[async_trait::async_trait]
    impl TokenStore for NoopStore {
        async fn load(&self) -> Result<Option<TokenSet>, TokenStoreError> {
            Ok(None)
        }

        async fn save(&self, _tokens: &TokenSet) -> Result<(), TokenStoreError> {
            Ok(())
        }

        async fn clear(&self) -> Result<(), TokenStoreError> {
            Ok(())
        }
    }

    fn make_token_set() -> TokenSet {
        TokenSet::new(
            "access".to_string(),
            None,
            Some(SystemTime::now() + Duration::from_secs(3600)),
            "Bearer".to_string(),
            None,
            Vec::new(),
        )
        .into_validated()
    }

    #[tokio::test]
    async fn noop_store_load_returns_none() {
        let store = NoopStore;
        let result = store.load().await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn noop_store_save_returns_ok() {
        let store = NoopStore;
        let tokens = make_token_set();
        let result = store.save(&tokens).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn noop_store_clear_returns_ok() {
        let store = NoopStore;
        let result = store.clear().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn token_store_is_object_safe() {
        let store: Box<dyn TokenStore> = Box::new(NoopStore);
        let result = store.load().await;
        assert!(matches!(result, Ok(None)));
    }
}
