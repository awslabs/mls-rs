use super::*;
use crate::client_config::ClientConfig;

#[derive(Clone, Debug)]
pub struct GroupStats {
    pub total_leaves: usize,
    pub current_index: u32,
    pub direct_path: Vec<Option<HpkePublicKey>>,
    pub epoch: u64,
}

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    pub fn group_stats(&self) -> Result<GroupStats, GroupError> {
        Ok(GroupStats {
            total_leaves: self.roster().len(),
            current_index: self.current_member_index(),
            direct_path: self.current_direct_path()?,
            epoch: self.current_epoch(),
        })
    }
}
