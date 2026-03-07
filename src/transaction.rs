//! WFP Transaction wrapper with RAII rollback
//!
//! Provides safe transaction management for WFP operations with automatic rollback on error.

use crate::engine::WfpEngine;
use crate::errors::{WfpError, WfpResult};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};

/// WFP Transaction with RAII rollback support
///
/// Automatically begins a transaction on creation and rolls back on drop
/// unless explicitly committed.
///
/// # Examples
///
/// ```no_run
/// use windows_wfp::{WfpEngine, WfpTransaction};
///
/// let engine = WfpEngine::new()?;
/// let mut txn = WfpTransaction::begin(&engine)?;
///
/// // Perform filter operations...
/// // If any operation fails, transaction will be rolled back automatically
///
/// txn.commit()?; // Explicitly commit if all succeeded
/// # Ok::<(), windows_wfp::WfpError>(())
/// ```
pub struct WfpTransaction<'a> {
    /// Reference to the WFP engine
    engine: &'a WfpEngine,
    /// Whether the transaction has been committed
    committed: bool,
}

impl<'a> WfpTransaction<'a> {
    /// Begin a new WFP transaction
    ///
    /// The transaction will automatically rollback if dropped without calling `commit()`.
    ///
    /// # Errors
    ///
    /// Returns `WfpError::TransactionBeginFailed` if:
    /// - Another transaction is already active on this session
    /// - WFP engine session is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use windows_wfp::{WfpEngine, WfpTransaction};
    ///
    /// let engine = WfpEngine::new()?;
    /// let mut txn = WfpTransaction::begin(&engine)?;
    /// // Transaction active...
    /// txn.commit()?;
    /// # Ok::<(), windows_wfp::WfpError>(())
    /// ```
    pub fn begin(engine: &'a WfpEngine) -> WfpResult<Self> {
        unsafe {
            let result = FwpmTransactionBegin0(engine.handle(), 0);

            if result != ERROR_SUCCESS.0 {
                return Err(WfpError::TransactionBeginFailed);
            }
        }

        Ok(Self {
            engine,
            committed: false,
        })
    }

    /// Commit the transaction
    ///
    /// Makes all changes permanent. If not called, the transaction will
    /// automatically rollback when dropped.
    ///
    /// # Errors
    ///
    /// Returns `WfpError::TransactionCommitFailed` if the commit operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use windows_wfp::{WfpEngine, WfpTransaction};
    ///
    /// let engine = WfpEngine::new()?;
    /// let mut txn = WfpTransaction::begin(&engine)?;
    /// // Perform operations...
    /// txn.commit()?; // Make changes permanent
    /// # Ok::<(), windows_wfp::WfpError>(())
    /// ```
    pub fn commit(mut self) -> WfpResult<()> {
        unsafe {
            let result = FwpmTransactionCommit0(self.engine.handle());

            if result != ERROR_SUCCESS.0 {
                return Err(WfpError::TransactionCommitFailed);
            }
        }

        self.committed = true;
        Ok(())
    }

    /// Explicitly rollback the transaction
    ///
    /// This is optional - the transaction will rollback automatically on drop
    /// if not committed. Use this for explicit error handling.
    ///
    /// # Errors
    ///
    /// Returns `WfpError::TransactionAbortFailed` if the abort operation fails.
    pub fn rollback(mut self) -> WfpResult<()> {
        unsafe {
            let result = FwpmTransactionAbort0(self.engine.handle());

            if result != ERROR_SUCCESS.0 {
                return Err(WfpError::TransactionAbortFailed);
            }
        }

        self.committed = true; // Prevent double-abort in drop
        Ok(())
    }

    /// Check if transaction has been committed
    pub fn is_committed(&self) -> bool {
        self.committed
    }
}

impl<'a> Drop for WfpTransaction<'a> {
    /// Automatically rollback transaction if not committed
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                // Best effort rollback - ignore errors in drop
                let _ = FwpmTransactionAbort0(self.engine.handle());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires admin privileges
    fn test_transaction_begin_commit() {
        let engine = WfpEngine::new().expect("Failed to create engine");
        let txn = WfpTransaction::begin(&engine).expect("Failed to begin transaction");

        assert!(!txn.is_committed());

        txn.commit().expect("Failed to commit transaction");
    }

    #[test]
    #[ignore] // Requires admin privileges
    fn test_transaction_auto_rollback() {
        let engine = WfpEngine::new().expect("Failed to create engine");

        {
            let _txn = WfpTransaction::begin(&engine).expect("Failed to begin transaction");
            // Transaction should rollback automatically when dropped
        }

        // Should be able to begin a new transaction after rollback
        let _txn2 = WfpTransaction::begin(&engine).expect("Failed to begin second transaction");
    }

    #[test]
    #[ignore] // Requires admin privileges
    fn test_transaction_explicit_rollback() {
        let engine = WfpEngine::new().expect("Failed to create engine");
        let txn = WfpTransaction::begin(&engine).expect("Failed to begin transaction");

        txn.rollback().expect("Failed to rollback transaction");

        // Should be able to begin a new transaction after rollback
        let _txn2 = WfpTransaction::begin(&engine).expect("Failed to begin second transaction");
    }
}
