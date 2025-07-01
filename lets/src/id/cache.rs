use identity_demia::demia::{DemiaDID, DemiaDocument};

#[cfg(feature = "did")]
#[async_trait::async_trait]
pub trait IdentityCache {
    /// Returns the `DID` document for the given `DID`.
    async fn get_did_document(&self, did: &DemiaDID) -> Option<DemiaDocument>;
    
    /// Sets the `DID` document for the given `DID`.
    async fn set_did_document(&mut self, did: DemiaDID, document: DemiaDocument);
    
    /// Checks size of cache
    async fn size(&self) -> usize;
}