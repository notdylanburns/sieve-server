use serde::Deserialize;

#[derive(Deserialize)]
pub struct PaginationParams {
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

impl PaginationParams {
    pub fn offset(&self) -> Option<i64> {
        self.offset.map(i64::from)
    }

    pub fn limit(&self) -> Option<i64> {
        self.limit.map(i64::from)
    }
}
